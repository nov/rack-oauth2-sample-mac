class AccessToken < ActiveRecord::Base
  include Oauth2Token
  self.default_lifetime = 15.minutes
  belongs_to :refresh_token

  validates :secret, :presence => true
  validates :algorithm, :presence => true, :inclusion => [
    'hmac-sha-1',
    'hmac-sha-256'
  ]

  def to_mac_token(with_refresh_token = false)
    mac_token = Rack::OAuth2::AccessToken::MAC.new(
      :access_token  => self.token,
      :mac_key       => self.secret,
      :mac_algorithm => self.algorithm,
      :expires_in    => self.expires_in
    )
    if with_refresh_token
      mac_token.refresh_token = self.create_refresh_token(
        :account => self.account,
        :client  => self.client
      ).token
    end
    mac_token
  end

  private

  def setup
    super
    self.algorithm = 'hmac-sha-256'
    self.secret = SecureToken.generate
    if refresh_token
      self.account = refresh_token.account
      self.client = refresh_token.client
      self.expires_at = [self.expires_at, refresh_token.expires_at].min
    end
  end
end
