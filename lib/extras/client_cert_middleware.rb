class ClientCertMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    env['SSL_CLIENT_CERT'] = IO.read(ENV['SSL_CLIENT_CERT']) if File.exists?(ENV['SSL_CLIENT_CERT'])
    @status, @headers, @response = @app.call(env)
    [@status, @headers, @response]
  end
end