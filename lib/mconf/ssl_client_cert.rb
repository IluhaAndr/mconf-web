module Mconf
  class SSLClientCert

    def initialize cert_str
      @user, @error = nil, nil

      if certificate_login_enabled? && cert_str.present?
        @certificate = read_cert(cert_str)
        @private_key = get_private_key

        if @certificate.verify(@private_key)
          attrs = {}
          attrs[user_field] = get_field(certificate_id_field)
          @user = User.where(attrs).first

          if @user.blank?
            @error = :not_found
          end
        else
          @error = :verify
        end

      else
        @error = :certificate
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
      Site.current.certificate_login_enabled? &&
      certificate_id_field.present?
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
      OpenSSL::X509::Certificate.new(cert_str)
    end

    def get_private_key
      OpenSSL::PKey::RSA.new(File.read('config/cakey.pem'), 'mconf')
    end

    def get_field field_name
      @certificate.subject.to_s.match(/#{field_name}=(.*)/)[1]
    end

  end
end