module SimpleSaml
  module ResponseHandler
    @@fields = []

    def self.handle_type(type_field = :type)
      field type_field
    end

    def self.field(name, options={})
      field = {}
      field[:name] = name
      field[:to] = options[:to] || name
      field[:multiple] = options[:multiple] || false
      field[:convert] = options[:convert].respond_to?(:call) ? options[:convert] : nil
      @@fields << field
    end

    def self.normalize_attributes(attrs)
      result = {}
      attrs = attrs.map{|k, v| [k.to_sym, v] }.to_h

      @@fields.each do |f|
        if value = attrs[f[:name].to_sym]
          value = value.is_a?(Array) ? (f[:multiple] ? value : value[0]) : value

          value = f[:convert] ?
            (value.is_a?(Array) ? value.map{ |e| f[:convert].call(e) } :
            f[:convert].call(value)) : value

          result[f[:to].to_s] = value
        end
      end
      result
    end
  end
end
