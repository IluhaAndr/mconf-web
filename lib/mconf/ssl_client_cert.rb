module Mconf
  class SSLClientCert

    def initialize cert_str
      @user, @error = nil, nil

      if !certificate_login_enabled?
        @error = :not_enabled
        return
      end

      @certificate = read_cert(cert_str)
      @private_key = get_private_key

      if @certificate.blank?
        @error = :certificate
        return
      end

      if @private_key.blank?
        @error = :private_key
        return
      end

      if @certificate.verify(@private_key)
        attrs = {}
        attrs[user_field] = get_field(certificate_id_field)
        @user = User.where(attrs).first

        @error = :not_found if @user.blank?
      else
        @error = :verify
      end

    end

    def error
      @error
    end

    def user
      @user
    end

    private
    def certificate_login_enabled?
      Site.current.certificate_login_enabled? && certificate_id_field.present?
    end

    # The unique field in the certificate
    def certificate_id_field
      Site.current.certificate_id_field
    end

    # The unique field in the user model which should be linked to the certificate
    def user_field
      Site.current.certificate_user_id_field || 'email'
    end

    # Read cert attributes using OpenSSL
    def read_cert cert_str
      begin
        OpenSSL::X509::Certificate.new(cert_str.to_s)
      rescue OpenSSL::X509::CertificateError
        nil
      end
    end

    def get_private_key
      begin
        OpenSSL::PKey::RSA.new(File.read(private_key_file), private_key_password)
      rescue OpenSSL::PKey::RSAError, Errno::ENOENT # wrong key password of key not found
        nil
      end
    end

    def get_field field_name
      @certificate.subject.to_s.match(/#{field_name}=(.*)/)[1]
    end

    def private_key_file
      ENV['SSL_CLIENT_CERT_PRIVATE_KEY_FILE']
    end

    def private_key_password
      ENV['SSL_CLIENT_CERT_PRIVATE_KEY_PASSWORD']
    end

  end
end