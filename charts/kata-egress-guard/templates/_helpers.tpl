{{- define "kata-egress-guard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "kata-egress-guard.fullname" -}}
{{- default (printf "%s-%s" .Release.Name (include "kata-egress-guard.name" .)) .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "kata-egress-guard.labels" -}}
app.kubernetes.io/name: {{ include "kata-egress-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "kata-egress-guard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kata-egress-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "kata-egress-guard.image" -}}
{{- $image := . -}}
{{- if $image.digest -}}{{ $image.repository }}@{{ $image.digest }}{{- else -}}{{ $image.repository }}:{{ required "image tag or digest is required" $image.tag }}{{- end -}}
{{- end }}
