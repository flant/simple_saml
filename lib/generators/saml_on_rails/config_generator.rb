module SamlOnRails
  class ConfigGenerator < Rails::Generators::Base
    source_root(File.expand_path(File.dirname(__FILE__)))


    def copy_initializer_file
      copy_file 'templates/initializer.rb', 'config/initializers/saml_on_rails.rb'
    end
  end
end
