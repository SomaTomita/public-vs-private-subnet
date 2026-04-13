##############################
# CloudWatch Dashboard — VPC Flow Logs Visualization
##############################
# Dashboard for visually inspecting network flows before and after an attack.
# Displays ACCEPT/REJECT trends, source IPs, and traffic by port.

resource "aws_cloudwatch_dashboard" "flow_logs" {
  dashboard_name = "${var.project_name}-flow-logs-dashboard"

  dashboard_body = jsonencode({
    widgets = [

      # ────────────────────────────────────────────────────
      # Row 1: Header text
      # ────────────────────────────────────────────────────
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = <<-EOT
# VPC Flow Logs Dashboard — ${var.project_name}
**Config**: `${var.config_mode}` | **Region**: `${var.aws_region}` | **VPC CIDR**: `${var.vpc_cidr}`

After running the attack scripts, check this dashboard to observe the differences between ACCEPT and REJECT traffic.
EOT
        }
      },

      # ────────────────────────────────────────────────────
      # Row 2: ACCEPT vs REJECT time series (line chart)
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 2
        width  = 12
        height = 6
        properties = {
          title   = "ACCEPT / REJECT Traffic Trend"
          region  = var.aws_region
          query   = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total by bin(1m) as time, action | sort time asc"
          view    = "timeSeries"
          stacked = false
        }
      },

      # ACCEPT vs REJECT bar chart
      {
        type   = "log"
        x      = 12
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "ACCEPT / REJECT Count (Bar Chart)"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total by action"
          view   = "bar"
        }
      },

      # ────────────────────────────────────────────────────
      # Row 3: Top 10 Source IPs (table)
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 8
        width  = 12
        height = 6
        properties = {
          title  = "Top 10 Source IPs"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total, sum(packets) as pkts, sum(bytes) as byts by srcAddr | sort total desc | limit 10"
          view   = "table"
        }
      },

      # Top 10 Destination IPs (table)
      {
        type   = "log"
        x      = 12
        y      = 8
        width  = 12
        height = 6
        properties = {
          title  = "Top 10 Destination IPs"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total, sum(packets) as pkts by dstAddr | sort total desc | limit 10"
          view   = "table"
        }
      },

      # ────────────────────────────────────────────────────
      # Row 4: Traffic by port
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 14
        width  = 12
        height = 6
        properties = {
          title  = "Traffic by Destination Port (Pie Chart)"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total by dstPort | sort total desc | limit 10"
          view   = "pie"
        }
      },

      # ACCEPT/REJECT by port
      {
        type   = "log"
        x      = 12
        y      = 14
        width  = 12
        height = 6
        properties = {
          title  = "ACCEPT / REJECT Breakdown by Port"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total by dstPort, action | sort total desc | limit 20"
          view   = "table"
        }
      },

      # ────────────────────────────────────────────────────
      # Row 5: Rejected traffic details
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 20
        width  = 24
        height = 6
        properties = {
          title  = "Rejected Traffic (Blocked by SG/NACL)"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | filter action = 'REJECT' | stats count(*) as blocked, sum(packets) as pkts by srcAddr, dstAddr, dstPort | sort blocked desc | limit 20"
          view   = "table"
        }
      },

      # ────────────────────────────────────────────────────
      # Row 6: External attack pattern detection
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 26
        width  = 12
        height = 6
        properties = {
          title  = "External IP -> Internal IP Traffic (Potential Attacks)"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | filter not srcAddr like '10.0.' | filter dstAddr like '10.0.' | stats count(*) as total by srcAddr, dstPort, action | sort total desc | limit 15"
          view   = "table"
        }
      },

      # Time series: REJECT from external sources
      {
        type   = "log"
        x      = 12
        y      = 26
        width  = 12
        height = 6
        properties = {
          title   = "Rejected Traffic from External Sources Trend"
          region  = var.aws_region
          query   = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | filter action = 'REJECT' | filter not srcAddr like '10.0.' | stats count(*) as rejected by bin(1m) as time | sort time asc"
          view    = "timeSeries"
          stacked = false
        }
      },

      # ────────────────────────────────────────────────────
      # Row 7: Packet/byte volume trend
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 32
        width  = 12
        height = 6
        properties = {
          title   = "Packet Count Trend"
          region  = var.aws_region
          query   = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats sum(packets) as pkts by bin(1m) as time, action | sort time asc"
          view    = "timeSeries"
          stacked = true
        }
      },

      {
        type   = "log"
        x      = 12
        y      = 32
        width  = 12
        height = 6
        properties = {
          title   = "Data Transfer Volume Trend (Bytes)"
          region  = var.aws_region
          query   = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats sum(bytes) as byts by bin(1m) as time, action | sort time asc"
          view    = "timeSeries"
          stacked = true
        }
      },

      # ────────────────────────────────────────────────────
      # Row 8: Internal communication visualization
      # ────────────────────────────────────────────────────
      {
        type   = "log"
        x      = 0
        y      = 38
        width  = 12
        height = 6
        properties = {
          title  = "Internal Communication (App <-> RDS, etc.)"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | filter srcAddr like '10.0.' and dstAddr like '10.0.' | stats count(*) as total, sum(packets) as pkts by srcAddr, dstAddr, dstPort, action | sort total desc | limit 15"
          view   = "table"
        }
      },

      # By protocol
      {
        type   = "log"
        x      = 12
        y      = 38
        width  = 12
        height = 6
        properties = {
          title  = "Traffic by Protocol"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.flow_logs.name}' | stats count(*) as total by protocol | sort total desc"
          view   = "pie"
        }
      }
    ]
  })
}

##############################
# Dashboard URL output
##############################
output "dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-flow-logs-dashboard"
}
