{{- define "goca.name" -}}{{ .Chart.Name }}{{- end -}}

{{- define "goca.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "goca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "goca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "goca.labels" -}}
{{ include "goca.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* Refuse configurations that would silently lose or corrupt data. */}}
{{- define "goca.validate" -}}
{{- if ne .Values.database.driver "postgres" -}}
{{- fail "goca on Kubernetes runs on PostgreSQL only (database.driver=postgres): replicas share state through the database, and SQLite is a single file that concurrent pods would corrupt" -}}
{{- end -}}
{{- if not .Values.config.existingSecret -}}
{{- fail "config.existingSecret is required: goca's config.yaml holds the master key and must come from a Secret" -}}
{{- end -}}
{{- end -}}
