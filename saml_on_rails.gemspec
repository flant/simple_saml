$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "saml_on_rails/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "saml_on_rails"
  s.version     = SamlOnRails::VERSION
  s.authors     = ["Gennady Kalashnikov", "Serafim Nenarokov"]
  s.email       = ["gennady.kalashnikov@flant.ru", "serafim.nenarokov@flant.ru"]
  s.homepage    = "https://github.com/flant/saml_on_rails"
  s.summary     = "Summary of SamlOnRails."
  s.description = "Description of SamlOnRails."
  s.license     = "MIT"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  s.add_dependency "rails", ">= 5.0.0.beta2", "< 5.1"
end
