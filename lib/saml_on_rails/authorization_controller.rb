require_relative 'settings'

module SamlOnRails
  module AuthorizationController
    extend ActiveSupport::Concern
    included do
      skip_before_action :verify_authenticity_token, only: [:acs, :logout]

      def sso
        if session['nameid']
          redirect_to request.referer || after_login_url
        else
          request = OneLogin::RubySaml::Authrequest.new
          extra_params = {}
          extra_params[:RelayState] = params[:path] unless params[:path].blank?

          case saml_settings.idp_sso_target_binding
          when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            render "saml_on_rails/sso_post", locals: { saml_settings: saml_settings, request_params: request.create_params(saml_settings, extra_params) }, layout: false
          when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            redirect_to request.create(saml_settings, extra_params)
          else
            render_authorization_failure("unknown binding")
          end
        end
      end

      def acs
        response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: saml_settings)

        if response.is_valid?
          session[:nameid] = response.nameid
          handle_sso_response(response)

          # TODO: add extra param that will prevent infinite redirect
          redirect_to url_by_relay_state || after_login_url
        else
          render_authorization_failure(response.errors)
        end
      end

      def metadata
        render xml: saml_metadata
      end

      def sls
        if params[:SAMLRequest] # IdP initiated logout
          return idp_logout_request
        elsif params[:SAMLResponse]
          return process_logout_response
        end
      end

      # SLO or simple logout
      def logout
        if settings.slo_disabled? || saml_settings.idp_slo_target_url.nil?
          reset_session
          redirect_to after_logout_url
        else
          logout_request = OneLogin::RubySaml::Logoutrequest.new()
          session[:transaction_id] = logout_request.uuid

          unless saml_settings.name_identifier_value.present?
            saml_settings.name_identifier_value = session[:nameid]
          end

          case saml_settings.idp_sso_target_binding
          when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            extra_params = { :RelayState => request.referer }
            render "saml_on_rails/slo_post", locals: { saml_settings: saml_settings, request_params: logout_request.create_params(saml_settings, extra_params) }, layout: false
          when "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            redirect_to logout_request.create(saml_settings, RelayState: after_logout_url)
          end
        end
      end

      def process_logout_response
        logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], saml_settings, matches_request_id: session[:transaction_id], get_params: params)

        if logout_response.validate && logout_response.success?
          reset_session
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
          reset_session
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
          return '/' + CGI.unescape(params[:RelayState])
        end
      end

      def handle_sso_response(response)
        attrs = SamlOnRails::ResponseHandler.normalize_attributes(response.attributes.to_h)
        session[:user] = { SamlOnRails.user_key.to_s => attrs[SamlOnRails.user_key.to_s] }
        @current_user = SamlOnRails.user_class.handle_user_data(response.nameid, attrs)
      end

      def settings
        @@settings ||= SamlOnRails::Settings.new(request)
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
        raise NotImplementedError.new
      end

      def render_logout_failure(errors="")
        raise NotImplementedError.new
      end

      def render_logout_failure(errors="")
        render status: 404, json: {error: errors}, layout: false
      end
    end
  end

  module ApplicationController
    extend ActiveSupport::Concern
    included do
      protect_from_forgery with: :exception
      before_action :authenticate


      def authenticate
        if session[:user].blank?
          unauthenticated
        else
          @current_user = SamlOnRails.user_class.where(SamlOnRails.user_key => session[:user].try(:[], SamlOnRails.user_key.to_s)).first
          unauthenticated unless @current_user
        end
      end

      def unauthenticated
        ralay_path = params[:path] if params[:path] && params[:path]!=sso_saml_path

        query_params = params.to_h.except(:path, :controller, :action)
        ralay_path += "?" + CGI.unescape(query_params.to_query) if ralay_path && !query_params.blank?

        ralay_path = CGI.escape(ralay_path) if ralay_path
        redirect_to sso_saml_path(path: ralay_path)
      end

    end
  end
end

if defined? ActionController::Base
  ActionController::Base.class_eval do
    def self.saml_unauthorized_controller
      include SamlOnRails::AuthorizationController
    end

    def self.authorize_with_saml
      include SamlOnRails::ApplicationController
    end
  end
end
