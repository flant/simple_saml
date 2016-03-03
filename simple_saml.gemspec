$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "simple_saml/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "simple_saml"
  s.version     = SimpleSaml::VERSION
  s.authors     = ["Serafim Nenarokov"]
  s.email       = ["serafim.nenarokov@flant.ru"]
  s.homepage    = "https://github.com/flant/simple_saml"
  s.summary     = "Summary of SimpleSaml."
  s.description = "Description of SimpleSaml."
  s.license     = "MIT"

  s.files = Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]

  s.add_dependency "rails", ">= 5.0.0.beta2", "< 5.1"
end
