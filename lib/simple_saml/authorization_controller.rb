require_relative 'settings'
require_relative 'unauthenticated_error'

module SimpleSaml
  module AuthorizationController
    extend ActiveSupport::Concern
    included do
      skip_before_action :verify_authenticity_token, only: [:acs, :logout]
      skip_before_action :authenticate, except: [:logout]
      skip_before_action :check_ip_and_expiration, except: [:logout]

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
            session[:remote_addr] = request.ip
            session[:fake_user] = true

            attrs = SimpleSaml::ResponseHandler.normalize_attributes(user["attributes"])

            if @current_user = SimpleSaml.user_class.handle_user_data(attrs)
              session[:user] = { SimpleSaml.user_key.to_s => user["attributes"][SimpleSaml.user_key.to_s] }
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
        redirect_path = (params[:path] && CGI.unescape(params[:path])) || after_login_url

        if session['nameid'] && @current_user
          redirect_to redirect_path
        else
          saml_request = OneLogin::RubySaml::Authrequest.new
          extra_params = {}
          extra_params[:RelayState] = CGI.escape(redirect_path)

          case saml_settings.idp_sso_target_binding
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
          session[:remote_addr] = request.ip

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

          case s_settings.idp_sso_target_binding
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
        session[:user] = { SimpleSaml.user_key.to_s => attrs[SimpleSaml.user_key.to_s] }
        @current_user = SimpleSaml.user_class.handle_user_data(attrs)
      end

      def settings
        @@settings ||= SimpleSaml::Settings.new(request)
      end

      def saml_settings
        self.settings.saml_settings
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
  end

  module ApplicationController
    extend ActiveSupport::Concern

    included do
      attr_reader :current_user
      protect_from_forgery with: :exception
      before_action :authenticate
      before_action :check_ip_and_expiration

      helper_method :current_user

      def authenticate
        user_id = session[:user].try(:[], SimpleSaml.user_key.to_s)
        unless user_id.present?
          unauthenticated
        else
          @current_user = SimpleSaml.user_class
            .where(SimpleSaml.user_key => user_id).first
          unauthenticated unless @current_user
        end
      end

      def unauthenticated
        if request.format.html?
          relay_path = params[:path] if params[:path] && params[:path] != sso_saml_path

          query_params = params.to_unsafe_h.except(:path, :controller, :action)
          relay_path += "?" + CGI.unescape(query_params.to_query) if relay_path && !query_params.blank?
          relay_path = CGI.escape('/' + relay_path) if relay_path
          redirect_to sso_saml_path(path: relay_path)
        else
          raise SimpleSaml::UnauthenticatedError
        end
      end

      def check_ip_and_expiration
        request.session_options[:expire_after] = SimpleSaml.session_expire_after
        if session.key?(:remote_addr) && session[:remote_addr] != request.ip
          session.destroy
        elsif session.key?(:idp_session_expires_at) && session[:idp_session_expires_at] <= Time.now.to_i
          session.destroy
        end
      end
    end
  end
end

if defined? ActionController::Base
  ActionController::Base.class_eval do
    def self.saml_unauthorized_controller
      include SimpleSaml::AuthorizationController
    end

    def self.authorize_with_saml
      include SimpleSaml::ApplicationController
    end
  end

  ActionController::API.class_eval do
    def self.saml_unauthorized_controller
      include SimpleSaml::AuthorizationController
    end

    def self.authorize_with_saml
      include SimpleSaml::ApplicationController
    end
  end
end
