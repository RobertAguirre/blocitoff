class User < ActiveRecord::Base
  attr_accessor :login
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable, :confirmable,
         :recoverable, :rememberable, :trackable, :validatable
         
  validates :email,
             presence: true,
             uniqueness: { case_sensitive: false },
             length: { minimum: 3, maximum: 254 }


  def self.find_for_database_authentication(warden_conditions)
   conditions = warden_conditions.dup
     if login = conditions.delete(:login)
       where(conditions.to_h).where(["lower(email) = :value OR lower(email) = :value", { :value => login.downcase }]).first
     elsif conditions.has_key?(:email) || conditions.has_key?(:email)
       where(conditions.to_h).first
     end
  end
  
  def avatar_url(size)
    gravatar_id = Digest::MD5::hexdigest(self.email).downcase
    "http://gravatar.com/avatar/#{gravatar_id}.png?s=#{size}"
  end  
  
end
