require_relative 'saml_on_rails/engine'
require_relative 'saml_on_rails/authorization_controller'
require_relative 'saml_on_rails/routing_mapper'
require_relative 'saml_on_rails/response_handler'

module SamlOnRails
  mattr_accessor :user_class, :user_key, :session_expire_after

  @@user_class = nil
  @@user_key = :uuid
  @@session_expire_after = 20.minutes

  def self.config
    @@configured = true
    yield self
  end

  def self.response_fields
    yield SamlOnRails::ResponseHandler
  end
end
