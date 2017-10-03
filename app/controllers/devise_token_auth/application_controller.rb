module DeviseTokenAuth
  class ApplicationController < DeviseController
    include DeviseTokenAuth::Concerns::SetUserByToken

    before_action :set_csp_headers

    protected

    def params_for_resource(resource)
      devise_parameter_sanitizer.instance_values['permitted'][resource]
    end

    def serialized_resource
      ActiveModelSerializers::SerializableResource.new(
        @resource,
        serializer: get_serializer_for(resource_name),
        root: resource_name
      )
    end

    def resource_name
      :user
    end

    def resource_class(m=nil)
      if m
        mapping = Devise.mappings[m]
      else
        mapping = Devise.mappings[resource_name] || Devise.mappings.values.first
      end

      mapping.to
    end

    def set_csp_headers
      response.headers['Content-Security-Policy'] = ENV['CONTENT_SECURITY_POLICY']
    end
  end
end
