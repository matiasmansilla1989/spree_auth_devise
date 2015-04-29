module Spree
  class User < ActiveRecord::Base
    include UserAddress
    include UserPaymentSource

    devise :database_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :encryptable, 
           :encryptor => 'authlogic_sha512', request_keys: [:subdomain]

    devise :confirmable if Spree::Auth::Config[:confirmable]

    acts_as_paranoid
    # after_destroy :scramble_email_and_password

    has_many :orders

    ##### Admin User #####
    belongs_to  :admin_store, :class_name => 'Spree::Store', :foreign_key => 'store_admin_id'
    belongs_to  :customer_store, :class_name => 'Spree::Store', :foreign_key => 'store_customer_id'
    belongs_to  :store, :class_name => 'Spree::Store', :foreign_key => 'store_id'
    has_many    :products
    ##### Admin User #####

    users_table_name = User.table_name
    roles_table_name = Role.table_name

    scope :admin,   -> { includes(:spree_roles).where("#{roles_table_name}.name" => "admin") }
    scope :admins,  -> { joins(:spree_roles).where('spree_roles.name = "admin"') }
    scope :only_normal_users,  -> { joins(:spree_roles).where(
      'spree_roles.name != ?', "admin") }
    scope :from_current_store,  -> (store_id) { only_normal_users.where("store_customer_id = ?", store_id) }

    validates :email, presence: true
    validates :email, :uniqueness => {:scope => [:store_id]}
    validates :store_id, presence: true

    def self.admin_created?
      User.admin.count > 0
    end

    def admin?
      has_spree_role?('admin')
    end

    def customer?
      has_spree_role?('user')
    end

    protected
      def password_required?
        !persisted? || password.present? || password_confirmation.present?
      end


  end
end
