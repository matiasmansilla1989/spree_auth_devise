module Spree
  class User < ActiveRecord::Base
    include UserAddress
    include UserPaymentSource

    devise :database_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :validatable, :encryptable, :encryptor => 'authlogic_sha512'
    devise :confirmable if Spree::Auth::Config[:confirmable]

    acts_as_paranoid
    after_destroy :scramble_email_and_password

    has_many :orders

    ##### Admin User #####
    has_one     :store
    belongs_to  :customer_store, :class_name => 'Spree::Store', :foreign_key => 'store_customer_id'
    has_many    :products
    has_many    :option_types
    has_many    :properties
    has_many    :taxonomies
    has_many    :taxons
    ##### Admin User #####

    before_validation :set_login

    users_table_name = User.table_name
    roles_table_name = Role.table_name

    scope :admin,   -> { includes(:spree_roles).where("#{roles_table_name}.name" => "admin") }
    scope :admins,  -> { joins(:spree_roles).where('spree_roles.name = "admin"') }
    scope :only_normal_users,  -> { joins(:spree_roles).where(
      'spree_roles.name != ?', "admin") }
    scope :from_current_store,  -> (store_id) { only_normal_users.where("store_customer_id = ?", store_id) }

    def self.admin_created?
      User.admin.count > 0
    end

    def admin?
      has_spree_role?('admin')
    end

    protected
      def password_required?
        !persisted? || password.present? || password_confirmation.present?
      end

    private

      def set_login
        # for now force login to be same as email, eventually we will make this configurable, etc.
        self.login ||= self.email if self.email
      end

      def scramble_email_and_password
        self.email = SecureRandom.uuid + "@example.net"
        self.login = self.email
        self.password = SecureRandom.hex(8)
        self.password_confirmation = self.password
        self.save
      end
  end
end
