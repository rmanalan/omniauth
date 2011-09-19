require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # Authenticate to Atlassian (JIRA/Confluence) via OAuth and retrieve basic
    # user information.
    #
    # Usage:
    #    use OmniAuth::Strategies::Atlassian, 'consumerkey', 'rsaprivatekeyfile', 'siteurl', 'contextpath'
    class Atlassian < OmniAuth::Strategies::OAuth
      # Initialize the middleware
      #
      def initialize(app, consumer_key=nil, rsa_private_key=nil, site_url=nil, context_path='', options={}, &block)
        rsa_private_key = rsa_private_key
        @oa_context_path = context_path
        client_options = {
          :site => site_url,
          :signature_method => 'RSA-SHA1',
          :access_token_path => "#{@oa_context_path}/plugins/servlet/oauth/access-token",
          :authorize_path => "#{@oa_context_path}/plugins/servlet/oauth/authorize",
          :request_token_path => "#{@oa_context_path}/plugins/servlet/oauth/request-token"
        }
        super(app, :atlassian, consumer_key, rsa_private_key, client_options, options, &block)
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(
          super, {
            'uid' => @access_token.params[:oauth_token],
            'user_info' => user_info,
            'extra' => {
              'user_hash' => user_hash
            },
          }
        )
      end

      def user_info
        user_hash = self.user_hash
        {
          'id' => user_hash['id'],
          'name' => user_hash['name'],
          'display_name' => user_hash['displayName'],
          'email' => user_hash['emailAddress'],
          'avatar_small' => user_hash['avatarUrls']['16x16'],
          'avatar_square' => user_hash['avatarUrls']['48x48'],
          'active' => user_hash['active'],
          'timezone' => user_hash['timeZone'],
          'groups' => user_hash['groups']
        }
      end

      def user_hash
        @oa_session ||= MultiJson.decode(@access_token.get("#{@oa_context_path}/rest/auth/latest/session").body)
        @user_hash ||= MultiJson.decode(@access_token.get("#{@oa_context_path}/rest/api/latest/user?username=#{@oa_session['name']}&expand=groups").body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end
    end
  end
end
