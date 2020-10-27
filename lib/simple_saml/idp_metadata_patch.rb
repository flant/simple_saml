# TODO: any simplier method to get binding?

module IdpMetadataPatch
  def to_hash(options = {})
    super.merge(single_signon_service_binding: single_signon_service_binding(options[:sso_binding]),
                single_logout_service_binding: single_logout_service_binding(options[:slo_binding]))
  end
end

OneLogin::RubySaml::IdpMetadataParser.const_get('IdpMetadata').send(:prepend, IdpMetadataPatch)
