resource "st-cdnetworks_shared_config_ratelimit" "full" {
  rule_name   = "test"
  description = "all condition types created by terraform"
  statistical_items {
    statistical_item = "IP"
  }
  statistical_period = 120
  trigger_threshold  = 100
  intercept_time     = 300
  effective_status   = "PERMANENT"
  # rate_limit_effective = {
  #   effective = ["MON", "TUE", "WED", "THU", "FRI"]
  #   start     = "09:00"
  #   end       = "18:00"
  #   timezone  = "17"
  # }
  action = "IP_BLOCK"

  rate_limit_rule_condition {
    ip_or_ips_conditions {
      match_type = "EQUAL"
      ip_or_ips  = ["1.1.1.1", "10.0.0.0/24"]
    }

    path_conditions {
      match_type = "START_WITH"
      paths      = ["/api/"]
    }

    uri_conditions {
      match_type = "CONTAIN"
      uri        = ["/test.html?id=1"]
    }

    ua_conditions {
      match_type = "NOT_EQUAL"
      ua         = ["curl/8.0", "wget"]
    }

    method_conditions {
      match_type     = "EQUAL"
      request_method = ["GET", "POST"]
    }

    referer_conditions {
      match_type = "CONTAIN"
      referer    = ["example.com"]
    }

    header_conditions {
      match_type         = "EQUAL"
      key                = "x-m"
      value_list         = ["123"]
      key_match_wildcard = "FALSE"
    }

    area_conditions {
      match_type = "NOT_EQUAL"
      areas      = ["CN", "RU"]
    }

    scheme_conditions {
      match_type = "EQUAL"
      scheme     = ["HTTPS"]
    }

    status_code_conditions {
      match_type  = "EQUAL"
      status_code = ["404", "500"]
    }

    ja3_conditions {
      match_type = "EQUAL"
      ja3_list   = ["e7d705a3286e19ea42f587b347d17c67"]
    }

    ja4_conditions {
      match_type = "EQUAL"
      ja4_list   = ["t13d1516h2_8daaf6152771_b186095e22b6"]
    }

    asn_conditions {
      match_type = "EQUAL"
      asn_list   = ["15169", "13335"]
    }
  }
}

resource "st-cdnetworks_shared_config_ratelimit_association" "test" {
  share_id = st-cdnetworks_shared_config_ratelimit.full.id
  domain   = "api.sige-test3.com"
}
