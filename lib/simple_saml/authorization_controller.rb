require_relative 'settings'
require_relative 'unauthenticated_error'

module SimpleSaml
  module ControllerAdditions
    extend ActiveSupport::Concern

    module ClassMethods
      def saml_unauthorized_controller
        include SimpleSaml::AuthorizationController
      end

      def authorize_with_saml(attrs = {})
        include SimpleSaml::ApplicationController

        self.saml_user_classes = Array.wrap(attrs[:user_classes]) if attrs.key?(:user_classes)
      end
    end
  end

  module AuthorizationController
    extend ActiveSupport::Concern
    included do
      skip_before_action :verify_authenticity_token, only: [:acs, :logout]
      skip_before_action :authenticate, except: [:logout]
      skip_before_action :check_ip_and_expiration, except: [:logout]
    end

    ## Login

    def fakelogin
      redirect_path = (params[:path] && CGI.unescape(params[:path])) || after_login_url

      if session['nameid'] && @current_user
        redirect_to redirect_path
      else
        users = settings.fake_users
        if users.any? && users[params[:id]]
          user = users[params[:id]]
          session.destroy
          session[:nameid] = user["nameid"]
          session[:idp_session_expires_at] = user["idp_session_expires_at"]
          session[:remote_addr] = request.remote_ip
          session[:fake_user] = true

          attrs = SimpleSaml::ResponseHandler.normalize_attributes(user["attributes"])

          if authenticate_saml_user(attrs)
            redirect_to redirect_path
          else
            render_authorization_failure('Fakelogin error: provided user is not valid')
          end
        else
          render_authorization_failure("Fakelogin error: fake user not found")
        end
      end
    end

    def sso
      redirect_path = (params[:path] && CGI.unescape(params[:path])) ||
                      request.headers['X-Auth-Request-Original-Uri'] || request.headers['X-Original-Uri'] ||
                      after_login_url

      if session['nameid'] && @current_user
        redirect_to redirect_path
      else
        saml_request = OneLogin::RubySaml::Authrequest.new
        extra_params = {}
        extra_params[:RelayState] = CGI.escape(redirect_path)

        case settings.saml_sso_target_binding
        when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          render "simple_saml/sso_post", locals: { saml_settings: saml_settings, request_params: saml_request.create_params(saml_settings, extra_params) }, layout: false
        when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          redirect_to saml_request.create(saml_settings, extra_params)
        else
          render_authorization_failure("unknown binding")
        end
      end
    end

    def acs
      response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: saml_settings)

      if response.is_valid?
        session.destroy
        session[:nameid] = response.nameid
        session[:idp_session_expires_at] = response.session_expires_at if response.session_expires_at.present?
        session[:idp_session] = response.sessionindex if response.sessionindex.present?
        session[:remote_addr] = request.remote_ip

        if handle_sso_response(response)
          redirect_to url_by_relay_state || after_login_url
        else
          render_authorization_failure('Cannot create or update user')
        end
      else
        render_authorization_failure(response.errors)
      end
    end

    def metadata
      render xml: saml_metadata
    end

    ## Logout

    def logout
      return render_logout_failure("Logout failed") unless session[:nameid].present?

      if settings.slo_disabled? || saml_settings.idp_slo_target_url.nil? || session[:fake_user]
        session.destroy
        redirect_to after_logout_url
      else
        logout_request = OneLogin::RubySaml::Logoutrequest.new()
        session[:logout_request_id] = logout_request.uuid

        s_settings = saml_settings.dup
        s_settings.sessionindex = session[:idp_session] if session.key?(:idp_session)

        unless s_settings.name_identifier_value.present?
          s_settings.name_identifier_value = session[:nameid]
        end

        case settings.saml_slo_target_binding
        when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          extra_params = { :RelayState => after_logout_url }
          render "simple_saml/slo_post", locals: { saml_settings: s_settings, request_params: logout_request.create_params(s_settings, extra_params) }, layout: false
        when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          redirect_to logout_request.create(s_settings, RelayState: after_logout_url)
        end
      end
    end

    def sls
      if params[:SAMLRequest] # IdP initiated logout
        return idp_logout_request
      elsif params[:SAMLResponse]
        return process_logout_response
      end
    end

    def process_logout_response
      logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], saml_settings, matches_request_id: session[:logout_request_id], get_params: params)

      if logout_response.validate && logout_response.success?
        session.destroy
        redirect_to url_by_relay_state || after_logout_url
      else
        render_logout_failure(logout_response.errors)
      end
    end

    # TODO: test it and fix it
    def idp_logout_request
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(params[:SAMLRequest], settings: saml_settings)

      if !logout_request.is_valid?
        render_logout_failure(logout_request.errors)
      else
        session.destroy
        logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(saml_settings, logout_request.id, nil, RelayState: params[:RelayState])
        redirect_to logout_response
      end
    end

    protected

    def retrieve_saml_user(attrs)
      class_name = attrs['type'] || SimpleSaml.default_user_class

      klass = class_name.constantize

      if klass.respond_to?(:handle_user_data)
        klass.handle_user_data(attrs)
      else
        klass.where(SimpleSaml.user_key.to_s => attrs[SimpleSaml.saml_user_key.to_s]).first
      end
    end

    def authenticate_saml_user(attrs)
      setup_current_user(retrieve_saml_user(attrs))

      return false if @current_user.blank?

      saml_id = @current_user.public_send(SimpleSaml.user_key)
      session[:user] = { SimpleSaml.user_key.to_s => saml_id, 'type' => @current_user.class.to_s }
      true
    end

    def saml_metadata
      @@saml_metadata ||= OneLogin::RubySaml::Metadata.new.generate(saml_settings, true)
    end

    def url_by_relay_state
      if params[:RelayState].present?
        return CGI.unescape(params[:RelayState])
      end
    end

    def handle_sso_response(response)
      attrs = SimpleSaml::ResponseHandler.normalize_attributes(response.attributes.to_h)

      return authenticate_saml_user(attrs)
    end

    def settings
      @@settings ||= SimpleSaml::Settings.new(request)
    end

    def saml_settings
      self.settings.saml_settings
    end

    def setup_current_user(user)
      @current_user = user
    end

    def after_login_url
      raise NotImplementedError.new
    end

    def after_logout_url
      raise NotImplementedError.new
    end

    def render_authorization_failure(errors="")
      render status: 401, json: { error: errors }, layout: false
    end

    def render_logout_failure(errors="")
      render status: 401, json: { error: errors }, layout: false
    end
  end

  module ApplicationController
    extend ActiveSupport::Concern

    included do
      attr_reader :current_user
      before_action :check_ip_and_expiration
      before_action :authenticate

      helper_method :current_user

      class << self
        attr_accessor :saml_user_classes
      end

      delegate :saml_user_classes, to: :class
    end

    def authenticate
      unauthenticated unless authenticate_saml_user
    end

    def unauthenticated
      if request.format.html? && !session.key?(:user) # prevent endless reload on controller-called unauthenticated
        relay_path = if request.path == sso_saml_path
                       nil
                     else
                       path = request.path
                       path += "?#{request.query_string}" unless request.query_string.blank?
                       CGI.escape(path)
                     end

        redirect_to sso_saml_path(path: relay_path)
      else
        raise SimpleSaml::UnauthenticatedError
      end
    end

    def check_ip_and_expiration
      request.session_options[:expire_after] = SimpleSaml.session_expire_after
      if SimpleSaml.logout_on_ip_change && session.key?(:remote_addr) && session[:remote_addr] != request.remote_ip
        session.destroy
      elsif session.key?(:idp_session_expires_at) && session[:idp_session_expires_at] <= Time.now.to_i
        session.destroy
      end
    end

    protected

    def authenticate_saml_user
      return false unless (user_id = session[:user].try(:[], SimpleSaml.user_key.to_s))

      klass = session[:user].try(:[], 'type') || SimpleSaml.default_user_class
      return false if saml_user_classes && !saml_user_classes.include?(klass)

      @current_user = klass.constantize.where(SimpleSaml.user_key => user_id).first
    end
  end
end

ActionController::Base.send :include, SimpleSaml::ControllerAdditions if defined? ActionController::Base
ActionController::API.send  :include, SimpleSaml::ControllerAdditions if defined? ActionController::API
