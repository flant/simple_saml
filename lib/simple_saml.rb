require 'ruby-saml'

require_relative 'simple_saml/engine'
require_relative 'simple_saml/authorization_controller'
require_relative 'simple_saml/routing_mapper'
require_relative 'simple_saml/response_handler'

module SimpleSaml
  mattr_accessor :user_class, :user_key, :saml_user_key, :session_expire_after, :logout_on_ip_change

  @@user_class = nil
  @@user_key = :uuid
  @@saml_user_key = nil
  @@session_expire_after = 20.minutes
  @@logout_on_ip_change = true

  def self.config
    @@configured = true
    yield self
  end

  def self.user_class=(val)
    @@user_class = val.to_s
  end

  def self.saml_user_key
    @@saml_user_key || @@user_key
  end

  def self.user_class
    @@user_class.constantize
  end

  def self.response_fields
    yield SimpleSaml::ResponseHandler
  end
end
