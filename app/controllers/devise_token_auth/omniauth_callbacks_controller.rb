module DeviseTokenAuth
  class OmniauthCallbacksController < DeviseTokenAuth::ApplicationController

    attr_reader :auth_params
    skip_before_action :set_user_by_token, raise: false
    skip_after_action :update_auth_header

    def omniauth_success
      get_resource_from_auth_hash
      create_token_info
      set_token_on_resource
      create_auth_params

      if resource_class.devise_modules.include?(:confirmable)
        # don't send confirmation email!!!
        @resource.skip_confirmation!
      end

      sign_in(:user, @resource, store: false, bypass: false)

      @resource.save!

      yield if block_given?

      render_data_or_redirect('deliverCredentials', @auth_params.as_json, @resource.as_json)
    end

    def omniauth_failure
      @error = params[:message]
      render_data_or_redirect('authFailure', {error: @error})
    end

    protected

    # this will be determined differently depending on the action that calls
    # it. redirect_callbacks is called upon returning from successful omniauth
    # authentication, and the target params live in an omniauth-specific
    # request.env variable. this variable is then persisted thru the redirect
    # using our own dta.omniauth.params session var. the omniauth_success
    # method will access that session var and then destroy it immediately
    # after use.  In the failure case, finally, the omniauth params
    # are added as query params in our monkey patch to OmniAuth in engine.rb
    def omniauth_params
      params
    end

    # break out provider attribute assignment for easy method extension
    def assign_provider_attrs(user)
      user.assign_attributes({
        name:     (user.name || user_full_name),
        provider: auth_hash.provider,
        uid:      auth_hash.uid.gsub('https://openid.intuit.com/', '')
      })
    end

    def user_full_name
      full_name = [auth_hash.info.first_name, auth_hash.info.last_name].join(" ").squish
      full_name.present? ? full_name : auth_hash.info.name
    end

    # derive allowed params from the standard devise parameter sanitizer
    def whitelisted_params
      whitelist = params_for_resource(:sign_up)

      whitelist.inject({}){|coll, key|
        param = omniauth_params[key.to_s]
        if param
          coll[key] = param
        end
        coll
      }
    end

    def resource_class(mapping = nil)
      if omniauth_params['resource_class']
        omniauth_params['resource_class'].constantize
      else
        raise "No resource_class found"
      end
    end

    def omniauth_window_type
      omniauth_params['omniauth_window_type']
    end

    def auth_origin_url
      omniauth_params['auth_origin_url'] || omniauth_params['origin']
    end

    # this sesison value is set by the redirect_callbacks method. its purpose
    # is to persist the omniauth auth hash value thru a redirect. the value
    # must be destroyed immediatly after it is accessed by omniauth_success
    def auth_hash
      @_auth_hash ||= request.env['omniauth.auth'].except('extra')
    end

    # ensure that this controller responds to :devise_controller? conditionals.
    # this is used primarily for access to the parameter sanitizers.
    def assert_is_devise_resource!
      true
    end

    # necessary for access to devise_parameter_sanitizers
    def devise_mapping
      if omniauth_params
        Devise.mappings[omniauth_params['resource_class'].underscore.to_sym]
      else
        request.env['devise.mapping']
      end
    end

    def set_random_password
      # set crazy password for new oauth users. this is only used to prevent
        # access via email sign-in.
        p = SecureRandom.urlsafe_base64(nil, false)
        @resource.password = p
        @resource.password_confirmation = p
    end

    def create_token_info
      # create token info
      @client_id = SecureRandom.urlsafe_base64(nil, false)
      @token     = SecureRandom.urlsafe_base64(nil, false)
      @expiry    = (Time.now + DeviseTokenAuth.token_lifespan).to_i
      @config    = omniauth_params['config_name']
    end

    def create_auth_params
      @auth_params = {
        auth_token:     @token,
        client_id: @client_id,
        uid:       @resource.uid,
        expiry:    @expiry,
        config:    @config
      }
      @auth_params.merge!(oauth_registration: true) if @oauth_registration
      @auth_params
    end

    def set_token_on_resource
      @resource.tokens[@client_id] = {
        token: BCrypt::Password.create(@token),
        expiry: @expiry
      }
    end

    def render_data(message, data)
      @data = data.merge({
        message: message
      })
      render :layout => nil, :template => "devise_token_auth/omniauth_external_window"
    end

    def render_data_or_redirect(message, data, user_data = {})

      # We handle inAppBrowser and newWindow the same, but it is nice
      # to support values in case people need custom implementations for each case
      # (For example, nbrustein does not allow new users to be created if logging in with
      # an inAppBrowser)
      #
      # See app/views/devise_token_auth/omniauth_external_window.html.erb to understand
      # why we can handle these both the same.  The view is setup to handle both cases
      # at the same time.
      if ['inAppBrowser', 'newWindow'].include?(omniauth_window_type)
        render_data(message, user_data.merge(data))

      elsif auth_origin_url # default to same-window implementation, which forwards back to auth_origin_url

        # build and redirect to destination url
        redirect_to DeviseTokenAuth::Url.generate(auth_origin_url, data.merge(blank: true))
      else

        # there SHOULD always be an auth_origin_url, but if someone does something silly
        # like coming straight to this url or refreshing the page at the wrong time, there may not be one.
        # In that case, just render in plain text the error message if there is one or otherwise
        # a generic message.
        fallback_render data[:error] || 'An error occurred'
      end
    end

    def fallback_render(text)
        render inline: %Q|

            <html>
                    <head></head>
                    <body>
                            #{text}
                    </body>
            </html>|
    end

    def get_resource_from_auth_hash
      # find or create user by email
      @resource = find_or_initialize_resource

      if @resource.new_record?
        @oauth_registration = true
        set_random_password
      end

      # sync user info with provider, update/generate auth token
      assign_provider_attrs(@resource)

      # assign any additional (whitelisted) attributes
      extra_params = whitelisted_params
      @resource.assign_attributes(extra_params) if extra_params

      @resource
    end

    def find_or_initialize_resource
      email = auth_hash.info.email
      resource_class.find_for_authentication(email: email) || resource_class.new(email: email)
    end

  end
end
