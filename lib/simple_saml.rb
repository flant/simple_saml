require_relative 'simple_saml/engine'
require_relative 'simple_saml/authorization_controller'
require_relative 'simple_saml/routing_mapper'
require_relative 'simple_saml/response_handler'

module SimpleSaml
  mattr_accessor :user_class, :user_key, :session_expire_after

  @@user_class = nil
  @@user_key = :uuid
  @@session_expire_after = 20.minutes

  def self.config
    @@configured = true
    yield self
  end

  def self.user_class
    @@user_class = @@user_class.constantize if @@user_class.is_a?(String)
    @@user_class
  end

  def self.response_fields
    yield SimpleSaml::ResponseHandler
  end
end
