require 'ruby-saml'

require_relative 'simple_saml/engine'
require_relative 'simple_saml/authorization_controller'
require_relative 'simple_saml/routing_mapper'
require_relative 'simple_saml/response_handler'
require_relative 'simple_saml/idp_metadata_patch'

module SimpleSaml
  mattr_reader :default_user_class
  mattr_accessor :user_key, :saml_user_key, :session_expire_after, :logout_on_ip_change

  @@default_user_class = nil
  @@user_key = :uuid
  @@saml_user_key = nil
  @@session_expire_after = 20.minutes
  @@logout_on_ip_change = true

  def self.config
    @@configured = true
    yield self
  end

  def self.user_class=(val)
    warn 'Deprecated method `user_class=` is called, you should use `default_user_class=` instead.'

    self.default_user_class = val
  end

  def self.default_user_class=(val)
    @@default_user_class = val.to_s
  end

  def self.saml_user_key
    @@saml_user_key || @@user_key
  end

  def self.response_fields
    yield SimpleSaml::ResponseHandler
  end
end
