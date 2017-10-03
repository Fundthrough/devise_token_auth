module DeviseTokenAuth
  class ApplicationController < DeviseController
    include DeviseTokenAuth::Concerns::

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
      response.headers['Content-Security-Policy'] = "default-src 'self';
        style-src 'self' 'unsafe-inline'
          https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css
          https://appcenter.intuit.com/Content/IA/intuit.ipp.anywhere.css;
        font-src 'self'
          https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/fonts/
          https://js.intercomcdn.com/fonts/
          https://use.typekit.net/;
        script-src 'self' 'unsafe-eval'
          'sha256-Vi3CHlWsOlsRqMkqb9Gt6pky2DnJKzGGHkNUT3ikS2w='
          'sha256-qMGTRyHxXED7RJPHWK3TeFEE3LRBue8aWzyCsL5EoF4='
          'sha256-mFGhB5iVcN2mu/SUzixAIO8SaPgCgnCj2T6ZDhG9u10='
          localhost:35729/livereload.js
          http://0.0.0.0:3005/
          https://appcenter.intuit.com/
          http://cdn.segment.com/
          http://cdn.mxpnl.com/
          https://www.fullstory.com/
          https://widget.intercom.io/widget/
          https://api.segment.io/
          http://api.mixpanel.com/
          https://www.fullstory.com/
          https://js.intercomcdn.com/
          https://www.googletagmanager.com/
          https://use.typekit.net/
          http://js.bizographics.com/
          https://my.hellobar.com/
          https://snap.licdn.com/
          https://dc.ads.linkedin.com/
          https://px.ads.linkedin.com/
          https://us-east-1.dc.ads.linkedin.com/
          https://secure.adnxs.com/
          https://www.linkedin.com/
          https://www.bizographics.com/
          http://trackcmp.net/
          https://connect.facebook.net/
          https://d37gvrvc0wt4s1.cloudfront.net/
          https://sjs.bizographics.com/
          http://load.sumome.com/;
        connect-src 'self'
          ws://localhost:35729/
          http://0.0.0.0:3005/
          https://www.fullstory.com/
          http://api.mixpanel.com/
          https://api.segment.io/
          https://api-iam.intercom.io/
          https://nexus-websocket-a.intercom.io/
          https://nexus-websocket-b.intercom.io/
          wss://nexus-websocket-a.intercom.io/
          wss://nexus-websocket-b.intercom.io/
          https://nexus-long-poller-a.intercom.io/
          https://app.getsentry.com/
          https://performance.typekit.net/
          https://stage-jekyll.fundthrough.com/
          https://jekyll.fundthrough.com/
          http://sumo.com/;
        img-src 'self'
          data:
          blob:
          https://p.typekit.net/
          https://imp2.bizographics.com/
          https://secure.adnxs.com/
          https://cm.g.doubleclick.net/
          https://imp2.ads.linkedin.com/
          https://www.facebook.com/
          https://js.intercomcdn.com/
          https://static.intercomassets.com/;
        media-src 'self'
          https://js.intercomcdn.com/"
    end
  end
end
