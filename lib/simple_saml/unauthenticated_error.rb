module SimpleSaml
  class UnauthenticatedError < StandardError
    def message
      "Unauthenticated"
    end
  end
end
