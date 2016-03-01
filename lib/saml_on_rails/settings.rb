module SamlOnRails
  extend self

  def saml_settings(url_base)
    idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
    #@@idp_metadata ||= idp_metadata_parser.parse_remote(LOCAL_SETTINGS[:idp_metadata_url])
    settings = idp_metadata_parser.parse_remote(get_setting(:idp_metadata_url))

    #SP section
    settings.issuer                                = url_base + get_setting(:issuer_path, "/saml/metadata")
    settings.assertion_consumer_service_url        = url_base + get_setting(:consume_path, "/saml/acs")
    settings.assertion_consumer_logout_service_url = url_base + get_setting(:logout_path, "/saml/logout")

    settings.certificate = File.read(get_setting(:certificate_path))
    settings.private_key = File.read(get_setting(:private_key_path))

    # Security section
    settings.security[:authn_requests_signed] = true
    settings.security[:logout_requests_signed] = true
    settings.security[:logout_responses_signed] = true
    settings.security[:metadata_signed] = true

    settings.security[:digest_method] = XMLSecurity::Document::SHA1
    settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

    settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    settings.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    # Embeded signature or HTTP GET parameter signature
    # Note that metadata signature is always embedded regardless of this value.
    settings.security[:embed_sign] = false

    settings
  end

  protected

  def get_setting(key, default = nil)
    ENV.fetch("saml_#{key}".upcase) { default }
  end
end
