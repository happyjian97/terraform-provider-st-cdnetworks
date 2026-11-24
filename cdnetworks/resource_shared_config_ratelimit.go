package cdnetworks

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/myklst/terraform-provider-st-cdnetworks/cdnetworksapi"
)

// sharedConfigRatelimitResourceModel is the terraform model of the
// st-cdnetworks_shared_config_ratelimit resource.
type sharedConfigRatelimitResourceModel struct {
	Id                     types.String                 `tfsdk:"id"`
	ServiceType            types.String                 `tfsdk:"service_type"`
	RuleName               types.String                 `tfsdk:"rule_name"`
	Description            types.String                 `tfsdk:"description"`
	StatisticalItems       []statisticalItemModel       `tfsdk:"statistical_items"`
	StatisticalPeriod      types.Int64                  `tfsdk:"statistical_period"`
	TriggerThreshold       types.Int64                  `tfsdk:"trigger_threshold"`
	InterceptTime          types.Int64                  `tfsdk:"intercept_time"`
	EffectiveStatus        types.String                 `tfsdk:"effective_status"`
	RateLimitEffective     *rateLimitEffectiveModel     `tfsdk:"rate_limit_effective"`
	Action                 types.String                 `tfsdk:"action"`
	RedirectUrl            types.String                 `tfsdk:"redirect_url"`
	RateLimitRuleCondition *rateLimitRuleConditionModel `tfsdk:"rate_limit_rule_condition"`
}

type statisticalItemModel struct {
	StatisticalItem types.String `tfsdk:"statistical_item"`
	StatisticsKeys  []string     `tfsdk:"statistics_keys"`
}

type rateLimitEffectiveModel struct {
	Effective []string     `tfsdk:"effective"`
	Start     types.String `tfsdk:"start"`
	End       types.String `tfsdk:"end"`
	Timezone  types.String `tfsdk:"timezone"`
}

type rateLimitRuleConditionModel struct {
	IPOrIPsConditions    []ipOrIpsConditionModel    `tfsdk:"ip_or_ips_conditions"`
	PathConditions       []pathConditionModel       `tfsdk:"path_conditions"`
	URIConditions        []uriConditionModel        `tfsdk:"uri_conditions"`
	UAConditions         []uaConditionModel         `tfsdk:"ua_conditions"`
	MethodConditions     []methodConditionModel     `tfsdk:"method_conditions"`
	RefererConditions    []refererConditionModel    `tfsdk:"referer_conditions"`
	HeaderConditions     []headerConditionModel     `tfsdk:"header_conditions"`
	AreaConditions       []areaConditionModel       `tfsdk:"area_conditions"`
	SchemeConditions     []schemeConditionModel     `tfsdk:"scheme_conditions"`
	StatusCodeConditions []statusCodeConditionModel `tfsdk:"status_code_conditions"`
	JA3Conditions        []ja3ConditionModel        `tfsdk:"ja3_conditions"`
	JA4Conditions        []ja4ConditionModel        `tfsdk:"ja4_conditions"`
	ASNConditions        []asnConditionModel        `tfsdk:"asn_conditions"`
}

type ipOrIpsConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	IPOrIPs   []string     `tfsdk:"ip_or_ips"`
}

type pathConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	Paths     []string     `tfsdk:"paths"`
}

type uriConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	URI       []string     `tfsdk:"uri"`
}

type uaConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	UA        []string     `tfsdk:"ua"`
}

type methodConditionModel struct {
	MatchType     types.String `tfsdk:"match_type"`
	RequestMethod []string     `tfsdk:"request_method"`
}

type refererConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	Referer   []string     `tfsdk:"referer"`
}

type headerConditionModel struct {
	MatchType        types.String `tfsdk:"match_type"`
	ValueList        []string     `tfsdk:"value_list"`
	Key              types.String `tfsdk:"key"`
	KeyMatchWildcard types.String `tfsdk:"key_match_wildcard"`
}

type areaConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	Areas     []string     `tfsdk:"areas"`
}

type schemeConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	Scheme    []string     `tfsdk:"scheme"`
}

type statusCodeConditionModel struct {
	MatchType  types.String `tfsdk:"match_type"`
	StatusCode []string     `tfsdk:"status_code"`
}

type ja3ConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	JA3List   []string     `tfsdk:"ja3_list"`
}

type ja4ConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	JA4List   []string     `tfsdk:"ja4_list"`
}

type asnConditionModel struct {
	MatchType types.String `tfsdk:"match_type"`
	ASNList   []string     `tfsdk:"asn_list"`
}

type sharedConfigRatelimitResource struct {
	client *cdnetworksapi.Client
}

var (
	_ resource.Resource                = &sharedConfigRatelimitResource{}
	_ resource.ResourceWithConfigure   = &sharedConfigRatelimitResource{}
	_ resource.ResourceWithImportState = &sharedConfigRatelimitResource{}
)

func NewSharedConfigRatelimitResource() resource.Resource {
	return &sharedConfigRatelimitResource{}
}

func (r *sharedConfigRatelimitResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_shared_config_ratelimit"
}

func (r *sharedConfigRatelimitResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*cdnetworksapi.Client)
}

// Supported match types of the shared rate limit rule conditions.
var (
	sharedRatelimitEqualMatchTypes   = []string{"EQUAL", "NOT_EQUAL"}
	sharedRatelimitPathUriMatchTypes = []string{"EQUAL", "NOT_EQUAL", "CONTAIN", "NOT_CONTAIN", "REGEX", "NOT_REGEX", "START_WITH", "END_WITH", "WILDCARD", "NOT_WILDCARD"}
	sharedRatelimitContentMatchTypes = []string{"EQUAL", "NOT_EQUAL", "CONTAIN", "NOT_CONTAIN", "NONE", "REGEX", "NOT_REGEX", "START_WITH", "END_WITH", "WILDCARD", "NOT_WILDCARD"}
	sharedRatelimitJA4MatchTypes     = []string{"EQUAL", "NOT_EQUAL", "CONTAIN", "NOT_CONTAIN", "START_WITH", "END_WITH", "WILDCARD", "NOT_WILDCARD"}
)

func (r *sharedConfigRatelimitResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "This resource provides a shared configuration rate limit rule, which can be shared and associated with multiple domains.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "ID of the shared rate limit rule.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"service_type": schema.StringAttribute{
				Description: "Security service type, needed when multiple different security services are in use.",
				Optional:    true,
			},
			"rule_name": schema.StringAttribute{
				Description: "Rule name, up to 100 characters. '#' and '&' are not supported.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(100),
				},
			},
			"description": schema.StringAttribute{
				Description: "Rule description, up to 1000 characters.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1000),
				},
			},
			"statistical_period": schema.Int64Attribute{
				Description: "Statistical period in seconds, range: 1 - 3600.",
				Required:    true,
				Validators: []validator.Int64{
					int64validator.Between(1, 3600),
				},
			},
			"trigger_threshold": schema.Int64Attribute{
				Description: "Trigger threshold, in times.",
				Required:    true,
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"intercept_time": schema.Int64Attribute{
				Description: "Duration of the handling action in seconds, range: 10 - 604800.",
				Required:    true,
				Validators: []validator.Int64{
					int64validator.Between(10, 604800),
				},
			},
			"effective_status": schema.StringAttribute{
				Description: "Cycle effective status. Valid values: `PERMANENT` (effective permanently), `WITHOUT` (not effective within the period), `WITHIN` (effective within the period).",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("PERMANENT", "WITHOUT", "WITHIN"),
				},
			},
			"action": schema.StringAttribute{
				Description: "Handling action. Valid values: `NO_USE`, `LOG`, `COOKIE`, `JS_CHECK`, `JS_CHALLENGE`, `DELAY`, `BLOCK`, `RESET`, `IP_BLOCK`, `CUSTOM_ACTION_ID`, `FRIENDLY_PAGE`. When the match conditions contain status code, only `NO_USE`, `LOG`, `BLOCK`, `RESET`, `IP_BLOCK` and `CUSTOM_ACTION_ID` are supported.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("NO_USE", "LOG", "COOKIE", "JS_CHECK", "JS_CHALLENGE", "DELAY", "BLOCK", "RESET", "IP_BLOCK", "CUSTOM_ACTION_ID", "FRIENDLY_PAGE"),
				},
			},
			"redirect_url": schema.StringAttribute{
				Description: "Friendly page url to redirect to, required when `action` is `FRIENDLY_PAGE`.",
				Optional:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"statistical_items": schema.ListNestedBlock{
				Description: "Statistical granularity list.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"statistical_item": schema.StringAttribute{
							Description: "Statistical granularity. Valid values: `IP`, `UA`, `COOKIE`, `URL`, `HEADER`. `HEADER` is not supported when the match conditions contain status code.",
							Required:    true,
							Validators: []validator.String{
								stringvalidator.OneOf("IP", "UA", "COOKIE", "URL", "HEADER"),
							},
						},
						"statistics_keys": schema.ListAttribute{
							Description: "Key list when the statistical granularity is `COOKIE` or `HEADER`.",
							ElementType: types.StringType,
							Optional:    true,
						},
					},
				},
			},
			"rate_limit_effective": schema.SingleNestedBlock{
				Description: "Rule effective cycle. Required when `effective_status` is `WITHIN` or `WITHOUT`.",
				Attributes: map[string]schema.Attribute{
					"effective": schema.ListAttribute{
						Description: "Days of week when the rule takes effect. Valid values: `MON`, `TUE`, `WED`, `THU`, `FRI`, `SAT`, `SUN`.",
						ElementType: types.StringType,
						Optional:    true,
						Validators: []validator.List{
							listvalidator.ValueStringsAre(stringvalidator.OneOf("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")),
						},
					},
					"start": schema.StringAttribute{
						Description: "Start time, format: `HH:mm`.",
						Optional:    true,
					},
					"end": schema.StringAttribute{
						Description: "End time, format: `HH:mm`.",
						Optional:    true,
					},
					"timezone": schema.StringAttribute{
						Description: "Timezone, default: `GMT+8`. Refer to vendor documentation for valid values.",
						Optional:    true,
					},
				},
			},
			"rate_limit_rule_condition": schema.SingleNestedBlock{
				Description: "Match conditions of the rate limit rule.",
				Blocks: map[string]schema.Block{
					"ip_or_ips_conditions": schema.ListNestedBlock{
						Description: "IP/IP segment conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"ip_or_ips": schema.ListAttribute{
									Description: "IP/IP segment list, up to 500 IP/IP segments.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"path_conditions": schema.ListNestedBlock{
						Description: "Path conditions, match types cannot be duplicated. Not supported when the business scenario is API.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL` (case sensitive), `NOT_EQUAL` (case sensitive), `CONTAIN`, `NOT_CONTAIN`, `REGEX`, `NOT_REGEX`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`. `REGEX`/`NOT_REGEX` allows only one value.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitPathUriMatchTypes...),
									},
								},
								"paths": schema.ListAttribute{
									Description: "Path list. Paths of `EQUAL`/`NOT_EQUAL`/`START_WITH`/`END_WITH` must start with `/` and contain no parameters, e.g. `/test.html`.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"uri_conditions": schema.ListNestedBlock{
						Description: "URI conditions, match types cannot be duplicated. Not supported when the business scenario is API.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL` (case sensitive), `NOT_EQUAL` (case sensitive), `CONTAIN`, `NOT_CONTAIN`, `REGEX`, `NOT_REGEX`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`. `REGEX`/`NOT_REGEX` allows only one value.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitPathUriMatchTypes...),
									},
								},
								"uri": schema.ListAttribute{
									Description: "URI list. URIs of `EQUAL`/`NOT_EQUAL`/`START_WITH`/`END_WITH` must start with `/` and contain parameters, e.g. `/test.html?id=1`.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"ua_conditions": schema.ListNestedBlock{
						Description: "User-Agent conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL` (case sensitive), `NOT_EQUAL` (case sensitive), `CONTAIN`, `NOT_CONTAIN`, `NONE` (empty or not exist), `REGEX`, `NOT_REGEX`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`. `REGEX`/`NOT_REGEX` allows only one value.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitContentMatchTypes...),
									},
								},
								"ua": schema.ListAttribute{
									Description: "User-Agent list, e.g. `go-Http-client/1.1`. `REGEX`/`NOT_REGEX` allows only one value.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"method_conditions": schema.ListNestedBlock{
						Description: "Request method conditions, match types cannot be duplicated. Not supported when the business scenario is API.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"request_method": schema.ListAttribute{
									Description: "Request method list. Valid values: `GET`, `POST`, `DELETE`, `PUT`, `HEAD`, `OPTIONS`, `COPY`.",
									ElementType: types.StringType,
									Required:    true,
									Validators: []validator.List{
										listvalidator.ValueStringsAre(stringvalidator.OneOf("GET", "POST", "DELETE", "PUT", "HEAD", "OPTIONS", "COPY")),
									},
								},
							},
						},
					},
					"referer_conditions": schema.ListNestedBlock{
						Description: "Referer conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL` (case sensitive), `NOT_EQUAL` (case sensitive), `CONTAIN`, `NOT_CONTAIN`, `NONE` (empty or not exist), `REGEX`, `NOT_REGEX`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`. `REGEX`/`NOT_REGEX` allows only one value.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitContentMatchTypes...),
									},
								},
								"referer": schema.ListAttribute{
									Description: "Referer list, e.g. `http://test.com`. `REGEX`/`NOT_REGEX` allows only one value.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"header_conditions": schema.ListNestedBlock{
						Description: "Request header conditions, match types can be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL` (case sensitive), `NOT_EQUAL` (case sensitive), `CONTAIN`, `NOT_CONTAIN`, `NONE` (empty or not exist), `REGEX`, `NOT_REGEX`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`. `REGEX`/`NOT_REGEX` allows only one value.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitContentMatchTypes...),
									},
								},
								"value_list": schema.ListAttribute{
									Description: "Header value list. `REGEX`/`NOT_REGEX` allows only one value.",
									ElementType: types.StringType,
									Required:    true,
								},
								"key": schema.StringAttribute{
									Description: "Header name, case-insensitive, up to 100 characters, e.g. `Accept`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.LengthAtMost(100),
									},
								},
								"key_match_wildcard": schema.StringAttribute{
									Description: "Whether the header key matches wildcard. Valid values: `TRUE`, `FALSE`.",
									Optional:    true,
									Validators: []validator.String{
										stringvalidator.OneOf("TRUE", "FALSE"),
									},
								},
							},
						},
					},
					"area_conditions": schema.ListNestedBlock{
						Description: "Area conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"areas": schema.ListAttribute{
									Description: "Area list, refer to vendor documentation for valid values.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"scheme_conditions": schema.ListNestedBlock{
						Description: "Application layer protocol conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"scheme": schema.ListAttribute{
									Description: "Application layer protocol list. Valid values: `HTTP`, `HTTPS`.",
									ElementType: types.StringType,
									Required:    true,
									Validators: []validator.List{
										listvalidator.ValueStringsAre(stringvalidator.OneOf("HTTP", "HTTPS")),
									},
								},
							},
						},
					},
					"status_code_conditions": schema.ListNestedBlock{
						Description: "Status code conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"status_code": schema.ListAttribute{
									Description: "Status code list.",
									ElementType: types.StringType,
									Required:    true,
								},
							},
						},
					},
					"ja3_conditions": schema.ListNestedBlock{
						Description: "JA3 fingerprint conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"ja3_list": schema.ListAttribute{
									Description: "JA3 fingerprint list, up to 300 items. When match type is `EQUAL`/`NOT_EQUAL`, each item must be 32 characters of digits and lowercase letters.",
									ElementType: types.StringType,
									Required:    true,
									Validators: []validator.List{
										listvalidator.SizeAtMost(300),
									},
								},
							},
						},
					},
					"ja4_conditions": schema.ListNestedBlock{
						Description: "JA4 fingerprint conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`, `CONTAIN`, `NOT_CONTAIN`, `START_WITH`, `END_WITH`, `WILDCARD`, `NOT_WILDCARD`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitJA4MatchTypes...),
									},
								},
								"ja4_list": schema.ListAttribute{
									Description: "JA4 fingerprint list, up to 300 items. When match type is `EQUAL`/`NOT_EQUAL`, each item must be in the format of 10 characters + 12 characters + 12 characters separated by `_`, and only underscore, digits and lowercase letters are allowed.",
									ElementType: types.StringType,
									Required:    true,
									Validators: []validator.List{
										listvalidator.SizeAtMost(300),
									},
								},
							},
						},
					},
					"asn_conditions": schema.ListNestedBlock{
						Description: "ASN conditions, match types cannot be duplicated.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"match_type": schema.StringAttribute{
									Description: "Match type. Valid values: `EQUAL`, `NOT_EQUAL`.",
									Required:    true,
									Validators: []validator.String{
										stringvalidator.OneOf(sharedRatelimitEqualMatchTypes...),
									},
								},
								"asn_list": schema.ListAttribute{
									Description: "ASN list, positive integers within 1 - 4294967295.",
									ElementType: types.StringType,
									Required:    true,
									Validators: []validator.List{
										listvalidator.ValueStringsAre(
											stringvalidator.RegexMatches(regexp.MustCompile("^[1-9][0-9]{0,9}$"),
												"must be a positive integer within 1 - 4294967295"),
										),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *sharedConfigRatelimitResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model *sharedConfigRatelimitResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := validateSharedConfigRatelimitModel(model); err != nil {
		resp.Diagnostics.AddError("[Validate Config] Invalid config", err.Error())
		return
	}

	addResponse, err := r.client.AddSharedRateLimitRule(model.ServiceType.ValueString(), buildAddSharedRateLimitRuleRequest(model))
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Add SharedConfigRateLimit", err.Error())
		return
	}
	if addResponse.Code != 200 {
		resp.Diagnostics.AddError("[API ERROR] Fail to Add SharedConfigRateLimit", fmt.Sprintf("code: %s, msg: %s", addResponse.Code, addResponse.Msg))
		return
	}
	if addResponse.Data == "" {
		resp.Diagnostics.AddError("[API ERROR] Fail to Add SharedConfigRateLimit", "rule id is not returned by the API")
		return
	}
	model.Id = types.StringValue(addResponse.Data)

	// Best effort refresh with the rule returned by the query API to keep the
	// state consistent with the service. The rule may not be immediately
	// visible right after creation, so query errors are ignored and the
	// planned values are kept to avoid losing track of the created rule.
	if rule, err := findSharedRateLimitRule(r.client, model.Id.ValueString()); err == nil && rule != nil {
		updateModelFromRule(model, rule)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *sharedConfigRatelimitResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model *sharedConfigRatelimitResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, err := findSharedRateLimitRule(r.client, model.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Query SharedConfigRateLimit", err.Error())
		return
	}
	if rule == nil {
		// The shared rate limit rule no longer exists.
		resp.State.RemoveResource(ctx)
		return
	}

	updateModelFromRule(model, rule)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *sharedConfigRatelimitResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state *sharedConfigRatelimitResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Id = state.Id

	if err := validateSharedConfigRatelimitModel(plan); err != nil {
		resp.Diagnostics.AddError("[Validate Config] Invalid config", err.Error())
		return
	}

	updateResponse, err := r.client.UpdateSharedRateLimitRule(plan.ServiceType.ValueString(), buildUpdateSharedRateLimitRuleRequest(plan))
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Update SharedConfigRateLimit", err.Error())
		return
	}
	if updateResponse.Code != 200 {
		resp.Diagnostics.AddError("[API ERROR] Fail to Update SharedConfigRateLimit", fmt.Sprintf("code: %s, msg: %s", updateResponse.Code, updateResponse.Msg))
		return
	}

	// Best effort refresh, query errors are ignored and the planned values
	// are kept.
	if rule, err := findSharedRateLimitRule(r.client, plan.Id.ValueString()); err == nil && rule != nil {
		updateModelFromRule(plan, rule)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sharedConfigRatelimitResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var model *sharedConfigRatelimitResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip the API call if the rule has already been removed.
	rule, err := findSharedRateLimitRule(r.client, model.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Query SharedConfigRateLimit", err.Error())
		return
	}
	if rule == nil {
		return
	}

	deleteResponse, err := r.client.DeleteSharedRateLimitRules(model.ServiceType.ValueString(), &cdnetworksapi.DeleteSharedRateLimitRulesRequest{
		IDs: []string{model.Id.ValueString()},
	})
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Delete SharedConfigRateLimit", err.Error())
		return
	}
	if deleteResponse.Code != 200 {
		resp.Diagnostics.AddError("[API ERROR] Fail to Delete SharedConfigRateLimit", fmt.Sprintf("code: %s, msg: %s", deleteResponse.Code, deleteResponse.Msg))
		return
	}
}

func (r *sharedConfigRatelimitResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// validateSharedConfigRatelimitModel checks the cross field constraints of the
// model that cannot be expressed by schema validators.
func validateSharedConfigRatelimitModel(model *sharedConfigRatelimitResourceModel) error {
	if model.EffectiveStatus.ValueString() == "WITHIN" || model.EffectiveStatus.ValueString() == "WITHOUT" {
		if model.RateLimitEffective == nil {
			return fmt.Errorf("`rate_limit_effective` is required when `effective_status` is `WITHIN` or `WITHOUT`")
		}
	}

	if model.Action.ValueString() == "FRIENDLY_PAGE" && model.RedirectUrl.IsNull() {
		return fmt.Errorf("`redirect_url` is required when `action` is `FRIENDLY_PAGE`")
	}

	for _, item := range model.StatisticalItems {
		granularity := item.StatisticalItem.ValueString()
		if granularity == "COOKIE" || granularity == "HEADER" {
			if len(item.StatisticsKeys) == 0 {
				return fmt.Errorf("`statistics_keys` is required when `statistical_item` is `COOKIE` or `HEADER`")
			}
		}
	}

	return nil
}

// findSharedRateLimitRule queries the shared rate limit rule list and returns
// the rule with the given id, or nil if it does not exist.
func findSharedRateLimitRule(client *cdnetworksapi.Client, id string) (*cdnetworksapi.RateLimitRule, error) {
	getResponse, err := client.GetSharedRateLimitRules(&cdnetworksapi.GetSharedRateLimitRulesRequest{})
	if err != nil {
		return nil, err
	}
	if getResponse.Code != 200 {
		return nil, fmt.Errorf("code: %s, msg: %s", getResponse.Code, getResponse.Msg)
	}
	for i := range getResponse.Data {
		if getResponse.Data[i].ID == id {
			return &getResponse.Data[i], nil
		}
	}
	return nil, nil
}

// stringOrNull returns a null string when the value is empty, so that the
// state does not drift from a plan with an unset optional attribute.
func stringOrNull(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

// buildStatisticalItemsFromModel converts the statistical items of the model
// to the API representation.
func buildStatisticalItemsFromModel(items []statisticalItemModel) []cdnetworksapi.StatisticalItem {
	if items == nil {
		return nil
	}
	result := make([]cdnetworksapi.StatisticalItem, 0, len(items))
	for _, item := range items {
		result = append(result, cdnetworksapi.StatisticalItem{
			StatisticalItem: item.StatisticalItem.ValueString(),
			StatisticsKeys:  item.StatisticsKeys,
		})
	}
	return result
}

// buildRateLimitEffectiveFromModel converts the effective cycle of the model
// to the API representation.
func buildRateLimitEffectiveFromModel(effective *rateLimitEffectiveModel) *cdnetworksapi.RateLimitEffective {
	if effective == nil {
		return nil
	}
	return &cdnetworksapi.RateLimitEffective{
		Effective: effective.Effective,
		Start:     effective.Start.ValueString(),
		End:       effective.End.ValueString(),
		Timezone:  effective.Timezone.ValueString(),
	}
}

// buildRateLimitRuleConditionFromModel converts the match conditions of the
// model to the API representation.
func buildRateLimitRuleConditionFromModel(condition *rateLimitRuleConditionModel) *cdnetworksapi.RateLimitRuleCondition {
	if condition == nil {
		return nil
	}
	result := &cdnetworksapi.RateLimitRuleCondition{}
	for _, c := range condition.IPOrIPsConditions {
		result.IPOrIPsConditions = append(result.IPOrIPsConditions, cdnetworksapi.IPOrIPsCondition{
			MatchType: c.MatchType.ValueString(),
			IPOrIPs:   c.IPOrIPs,
		})
	}
	for _, c := range condition.PathConditions {
		result.PathConditions = append(result.PathConditions, cdnetworksapi.PathCondition{
			MatchType: c.MatchType.ValueString(),
			Paths:     c.Paths,
		})
	}
	for _, c := range condition.URIConditions {
		result.URIConditions = append(result.URIConditions, cdnetworksapi.URICondition{
			MatchType: c.MatchType.ValueString(),
			URI:       c.URI,
		})
	}
	for _, c := range condition.UAConditions {
		result.UAConditions = append(result.UAConditions, cdnetworksapi.UACondition{
			MatchType: c.MatchType.ValueString(),
			UA:        c.UA,
		})
	}
	for _, c := range condition.MethodConditions {
		result.MethodConditions = append(result.MethodConditions, cdnetworksapi.MethodCondition{
			MatchType:     c.MatchType.ValueString(),
			RequestMethod: c.RequestMethod,
		})
	}
	for _, c := range condition.RefererConditions {
		result.RefererConditions = append(result.RefererConditions, cdnetworksapi.RefererCondition{
			MatchType: c.MatchType.ValueString(),
			Referer:   c.Referer,
		})
	}
	for _, c := range condition.HeaderConditions {
		result.HeaderConditions = append(result.HeaderConditions, cdnetworksapi.HeaderCondition{
			MatchType:        c.MatchType.ValueString(),
			ValueList:        c.ValueList,
			Key:              c.Key.ValueString(),
			KeyMatchWildcard: c.KeyMatchWildcard.ValueString(),
		})
	}
	for _, c := range condition.AreaConditions {
		result.AreaConditions = append(result.AreaConditions, cdnetworksapi.AreaCondition{
			MatchType: c.MatchType.ValueString(),
			Areas:     c.Areas,
		})
	}
	for _, c := range condition.SchemeConditions {
		result.SchemeConditions = append(result.SchemeConditions, cdnetworksapi.SchemeCondition{
			MatchType: c.MatchType.ValueString(),
			Scheme:    c.Scheme,
		})
	}
	for _, c := range condition.StatusCodeConditions {
		result.StatusCodeConditions = append(result.StatusCodeConditions, cdnetworksapi.StatusCodeCondition{
			MatchType:  c.MatchType.ValueString(),
			StatusCode: c.StatusCode,
		})
	}
	for _, c := range condition.JA3Conditions {
		result.JA3Conditions = append(result.JA3Conditions, cdnetworksapi.JA3Condition{
			MatchType: c.MatchType.ValueString(),
			JA3List:   c.JA3List,
		})
	}
	for _, c := range condition.JA4Conditions {
		result.JA4Conditions = append(result.JA4Conditions, cdnetworksapi.JA4Condition{
			MatchType: c.MatchType.ValueString(),
			JA4List:   c.JA4List,
		})
	}
	for _, c := range condition.ASNConditions {
		result.ASNConditions = append(result.ASNConditions, cdnetworksapi.ASNCondition{
			MatchType: c.MatchType.ValueString(),
			ASNList:   c.ASNList,
		})
	}
	return result
}

// buildAddSharedRateLimitRuleRequest builds the add-rule request from the model.
func buildAddSharedRateLimitRuleRequest(model *sharedConfigRatelimitResourceModel) *cdnetworksapi.AddSharedRateLimitRuleRequest {
	return &cdnetworksapi.AddSharedRateLimitRuleRequest{
		RuleName:               model.RuleName.ValueString(),
		Description:            model.Description.ValueString(),
		StatisticalItems:       buildStatisticalItemsFromModel(model.StatisticalItems),
		StatisticalPeriod:      int(model.StatisticalPeriod.ValueInt64()),
		TriggerThreshold:       int(model.TriggerThreshold.ValueInt64()),
		InterceptTime:          int(model.InterceptTime.ValueInt64()),
		EffectiveStatus:        model.EffectiveStatus.ValueString(),
		RateLimitEffective:     buildRateLimitEffectiveFromModel(model.RateLimitEffective),
		Action:                 model.Action.ValueString(),
		RateLimitRuleCondition: buildRateLimitRuleConditionFromModel(model.RateLimitRuleCondition),
		RedirectURL:            model.RedirectUrl.ValueString(),
	}
}

// buildUpdateSharedRateLimitRuleRequest builds the update-rule request from the model.
func buildUpdateSharedRateLimitRuleRequest(model *sharedConfigRatelimitResourceModel) *cdnetworksapi.UpdateSharedRateLimitRuleRequest {
	return &cdnetworksapi.UpdateSharedRateLimitRuleRequest{
		ID:                     model.Id.ValueString(),
		RuleName:               model.RuleName.ValueString(),
		Description:            model.Description.ValueString(),
		StatisticalItems:       buildStatisticalItemsFromModel(model.StatisticalItems),
		StatisticalPeriod:      int(model.StatisticalPeriod.ValueInt64()),
		TriggerThreshold:       int(model.TriggerThreshold.ValueInt64()),
		InterceptTime:          int(model.InterceptTime.ValueInt64()),
		EffectiveStatus:        model.EffectiveStatus.ValueString(),
		RateLimitEffective:     buildRateLimitEffectiveFromModel(model.RateLimitEffective),
		Action:                 model.Action.ValueString(),
		RateLimitRuleCondition: buildRateLimitRuleConditionFromModel(model.RateLimitRuleCondition),
		RedirectURL:            model.RedirectUrl.ValueString(),
	}
}

// updateModelFromRule overwrites the model with the rule returned by the
// query API.
func updateModelFromRule(model *sharedConfigRatelimitResourceModel, rule *cdnetworksapi.RateLimitRule) {
	model.Id = types.StringValue(rule.ID)
	model.RuleName = types.StringValue(rule.RuleName)
	model.Description = stringOrNull(rule.Description)
	model.StatisticalItems = buildStatisticalItemsFromRule(rule.StatisticalItems)
	model.StatisticalPeriod = types.Int64Value(int64(rule.StatisticalPeriod))
	model.TriggerThreshold = types.Int64Value(int64(rule.TriggerThreshold))
	model.InterceptTime = types.Int64Value(int64(rule.InterceptTime))
	model.EffectiveStatus = types.StringValue(rule.EffectiveStatus)
	model.RateLimitEffective = buildRateLimitEffectiveFromRule(rule.RateLimitEffective)
	model.Action = types.StringValue(rule.Action)
	model.RedirectUrl = stringOrNull(rule.RedirectURL)
	model.RateLimitRuleCondition = buildRateLimitRuleConditionFromRule(rule.RateLimitRuleCondition)
}

// buildStatisticalItemsFromRule converts the statistical items of the API
// representation to the model.
func buildStatisticalItemsFromRule(items []cdnetworksapi.StatisticalItem) []statisticalItemModel {
	if items == nil {
		return nil
	}
	result := make([]statisticalItemModel, 0, len(items))
	for _, item := range items {
		result = append(result, statisticalItemModel{
			StatisticalItem: types.StringValue(item.StatisticalItem),
			StatisticsKeys:  item.StatisticsKeys,
		})
	}
	return result
}

// buildRateLimitEffectiveFromRule converts the effective cycle of the API
// representation to the model.
func buildRateLimitEffectiveFromRule(effective *cdnetworksapi.RateLimitEffective) *rateLimitEffectiveModel {
	if effective == nil || len(effective.Effective) == 0 {
		return nil
	}
	return &rateLimitEffectiveModel{
		Effective: effective.Effective,
		Start:     types.StringValue(effective.Start),
		End:       types.StringValue(effective.End),
		Timezone:  stringOrNull(effective.Timezone),
	}
}

// buildRateLimitRuleConditionFromRule converts the match conditions of the
// API representation to the model.
func buildRateLimitRuleConditionFromRule(condition *cdnetworksapi.RateLimitRuleCondition) *rateLimitRuleConditionModel {
	if condition == nil {
		return nil
	}
	result := &rateLimitRuleConditionModel{}
	for _, c := range condition.IPOrIPsConditions {
		result.IPOrIPsConditions = append(result.IPOrIPsConditions, ipOrIpsConditionModel{
			MatchType: types.StringValue(c.MatchType),
			IPOrIPs:   c.IPOrIPs,
		})
	}
	for _, c := range condition.PathConditions {
		result.PathConditions = append(result.PathConditions, pathConditionModel{
			MatchType: types.StringValue(c.MatchType),
			Paths:     c.Paths,
		})
	}
	for _, c := range condition.URIConditions {
		result.URIConditions = append(result.URIConditions, uriConditionModel{
			MatchType: types.StringValue(c.MatchType),
			URI:       c.URI,
		})
	}
	for _, c := range condition.UAConditions {
		result.UAConditions = append(result.UAConditions, uaConditionModel{
			MatchType: types.StringValue(c.MatchType),
			UA:        c.UA,
		})
	}
	for _, c := range condition.MethodConditions {
		result.MethodConditions = append(result.MethodConditions, methodConditionModel{
			MatchType:     types.StringValue(c.MatchType),
			RequestMethod: c.RequestMethod,
		})
	}
	for _, c := range condition.RefererConditions {
		result.RefererConditions = append(result.RefererConditions, refererConditionModel{
			MatchType: types.StringValue(c.MatchType),
			Referer:   c.Referer,
		})
	}
	for _, c := range condition.HeaderConditions {
		result.HeaderConditions = append(result.HeaderConditions, headerConditionModel{
			MatchType:        types.StringValue(c.MatchType),
			ValueList:        c.ValueList,
			Key:              types.StringValue(c.Key),
			KeyMatchWildcard: stringOrNull(c.KeyMatchWildcard),
		})
	}
	for _, c := range condition.AreaConditions {
		result.AreaConditions = append(result.AreaConditions, areaConditionModel{
			MatchType: types.StringValue(c.MatchType),
			Areas:     c.Areas,
		})
	}
	for _, c := range condition.SchemeConditions {
		result.SchemeConditions = append(result.SchemeConditions, schemeConditionModel{
			MatchType: types.StringValue(c.MatchType),
			Scheme:    c.Scheme,
		})
	}
	for _, c := range condition.StatusCodeConditions {
		result.StatusCodeConditions = append(result.StatusCodeConditions, statusCodeConditionModel{
			MatchType:  types.StringValue(c.MatchType),
			StatusCode: c.StatusCode,
		})
	}
	for _, c := range condition.JA3Conditions {
		result.JA3Conditions = append(result.JA3Conditions, ja3ConditionModel{
			MatchType: types.StringValue(c.MatchType),
			JA3List:   c.JA3List,
		})
	}
	for _, c := range condition.JA4Conditions {
		result.JA4Conditions = append(result.JA4Conditions, ja4ConditionModel{
			MatchType: types.StringValue(c.MatchType),
			JA4List:   c.JA4List,
		})
	}
	for _, c := range condition.ASNConditions {
		result.ASNConditions = append(result.ASNConditions, asnConditionModel{
			MatchType: types.StringValue(c.MatchType),
			ASNList:   c.ASNList,
		})
	}
	return result
}
