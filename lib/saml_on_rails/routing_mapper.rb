module SamlOnRails
  module RoutingMapper

    def saml_authorization(name, params={})
      resource name, params.merge(only: :index, path: :saml) do
        collection do
          get :sso
          post :acs
          post :sls
          get :metadata
          get :logout
        end
      end
    end

  end
end

if defined? ActionDispatch::Routing::Mapper
  ActionDispatch::Routing::Mapper.class_eval do
    include SamlOnRails::RoutingMapper
  end
end
