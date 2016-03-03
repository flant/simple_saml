SamlOnRails.config do |conf|
  ### Configure attributes, passed to User model
  response_fields do |c|
    # conf.field :first_name, multiple: false
    # conf.field :email, to: :e_mail, multiple: false, convert: ->(o) { o.gsub(/site\.net/, "site.com") }
  end

  # conf.session_expire_after = 20.minutes

  ### Configure user model
  # conf.user_class = User

  ### Configure user primary key
  ### default value is :uuid
  # conf.user_key = :id
end
