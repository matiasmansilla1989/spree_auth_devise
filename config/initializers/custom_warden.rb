module Devise
  module Strategies
    class Password < Base
      def valid?
        params.present? && params[:spree_user].present? && params[:spree_user][:email]
      end

      def authenticate!
        current_store =  Spree::Store.current(request.env['SERVER_NAME'])
        user = Spree::User.find_by(email: params[:spree_user][:email], subdomain: current_store.subdomain)
        if user.present? && user.valid_password?(params[:spree_user][:password])
          success! user
        else
          fail! :message => "strategies.password.failed"
        end
      end
    end
  end
end
