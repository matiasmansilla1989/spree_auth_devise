class Spree::Admin::UserSessionsController < Devise::SessionsController
  skip_before_filter :verify_authenticity_token, :only => :create
  helper 'spree/base'

  include Spree::Core::ControllerHelpers::Auth
  include Spree::Core::ControllerHelpers::Common
  include Spree::Core::ControllerHelpers::SSL
  include Spree::Core::ControllerHelpers::Store

  helper 'spree/admin/navigation'
  helper 'spree/admin/tables'
  layout 'spree/layouts/admin'

  skip_before_filter :require_no_authentication, :only => [:create]

  ssl_required :new, :create, :destroy, :update

  def create

    if current_store.admins.where(email: params[:spree_user][:email]).present?

      authenticate_spree_user!

      if spree_user_signed_in?
        respond_to do |format|
          format.html {
            if params[:spree_user][:social_square].blank?
              flash[:success] = Spree.t(:logged_in_succesfully)
              redirect_back_or_default(after_sign_in_path_for(spree_current_user))
            else
              redirect_to '/admin/orders'
            end
          }
          format.js {
            user = resource.record
            render :json => {:ship_address => user.ship_address, :bill_address => user.bill_address}.to_json
          }
        end
      else
        flash.now[:error] = t('devise.failure.invalid')
        render :new
      end
    else

      respond_to do |format|
        format.html {
          flash.now[:error] = 'Your user is not present in this store'
          render :new
        }
        format.js {
          render :json => { error: 'Your user is not present in this store' }, status: :unprocessable_entity
        }
      end
    end
  end

  def authorization_failure
  end

  private
    def accurate_title
      Spree.t(:login)
    end

    def redirect_back_or_default(default)
      redirect_to(session["spree_user_return_to"] || default)
      session["spree_user_return_to"] = nil
    end
end
