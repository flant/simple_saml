module SimpleSaml
  class Settings
    attr_reader :saml_settings, :base_url, :saml_sso_target_binding, :saml_slo_target_binding

    def initialize(request)
      setup_base_url(request)
      setup_saml
    end

    def setup_base_url(request)
      @base_url = request.protocol + request.host
    end

    def setup_saml
      @saml_settings = OneLogin::RubySaml::Settings.new

      # SP section
      @saml_settings.issuer                                = @base_url + "/saml/metadata"
      @saml_settings.assertion_consumer_service_url        = @base_url + "/saml/acs"
      @saml_settings.assertion_consumer_logout_service_url = @base_url + "/saml/logout"
      @saml_settings.single_logout_service_url             = @base_url + '/saml/sls'

      @saml_settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      @saml_settings.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

      @saml_settings.certificate = File.read(get_setting(:certificate_path))
      @saml_settings.private_key = File.read(get_setting(:private_key_path))

      # Security section
      @saml_settings.security[:authn_requests_signed] = !!@saml_settings.certificate
      @saml_settings.security[:logout_requests_signed] = !!@saml_settings.certificate
      @saml_settings.security[:logout_responses_signed] = !!@saml_settings.certificate
      @saml_settings.security[:metadata_signed] = !!@saml_settings.certificate

      @saml_settings.security[:embed_sign] = true

      @saml_settings.security[:digest_method] = XMLSecurity::Document::SHA256
      @saml_settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256

      # IDP section
      priority = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']

      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      @saml_settings = idp_metadata_parser.parse_remote(get_setting(:idp_metadata_url), true, settings: @saml_settings,
                                                                                              sso_binding: priority,
                                                                                              slo_binding: priority)
      @saml_sso_target_binding = idp_metadata_parser.send(:single_signon_service_binding, priority)
      @saml_slo_target_binding = idp_metadata_parser.send(:single_logout_service_binding, priority)

      @saml_settings
    end


    def slo_disabled?
      @slo_disabled ||= get_setting(:slo_disabled, false)
    end

    def fake_users
      users = get_setting(:fake_users, '{}')
      JSON.parse users
    end

    protected

    def get_setting(key, default = nil)
      val = ENV.fetch("saml_#{key}".upcase) { default }
      if val.in? ['true', 'false']
        val = val == 'true' ? true : false
      end
      val
    end
  end
end
