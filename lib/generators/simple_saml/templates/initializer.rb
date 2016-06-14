SimpleSaml.config do |conf|
  ### Configure attributes, passed to User model
  conf.response_fields do |c|
    # c.field :uuid
    # c.field :first_name
    # c.field :email, to: :e_mail, convert: ->(o) { o.gsub(/site\.net/, "site.com") }
    # c.field :tel_numbers, multiple: true
  end

  # conf.session_expire_after = 20.minutes

  ### Configure user model
  # conf.user_class = User

  ### Configure user primary key
  ### default value is :uuid
  # conf.user_key = :id

  ### Configure saml primary key
  ### default value is like user_key
  # conf.saml_user_key = :uuid
end
