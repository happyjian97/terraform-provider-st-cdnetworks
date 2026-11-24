package cdnetworks

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/myklst/terraform-provider-st-cdnetworks/cdnetworksapi"
)

// sharedConfigRatelimitAssociationIdSeparator separates the share id and the
// domain in the composite id of the association resource.
const sharedConfigRatelimitAssociationIdSeparator = ":"

// sharedConfigRatelimitAssociationModel is the terraform model of the
// st-cdnetworks_shared_config_ratelimit_association resource. It associates
// one domain with one shared rate limit rule.
type sharedConfigRatelimitAssociationModel struct {
	Id          types.String `tfsdk:"id"`
	ShareId     types.String `tfsdk:"share_id"`
	Domain      types.String `tfsdk:"domain"`
	ServiceType types.String `tfsdk:"service_type"`
}

type sharedConfigRatelimitAssociationResource struct {
	client *cdnetworksapi.Client
}

var (
	_ resource.Resource                = &sharedConfigRatelimitAssociationResource{}
	_ resource.ResourceWithConfigure   = &sharedConfigRatelimitAssociationResource{}
	_ resource.ResourceWithImportState = &sharedConfigRatelimitAssociationResource{}
)

func NewSharedConfigRatelimitAssociationResource() resource.Resource {
	return &sharedConfigRatelimitAssociationResource{}
}

func (r *sharedConfigRatelimitAssociationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_shared_config_ratelimit_association"
}

func (r *sharedConfigRatelimitAssociationResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "This resource associates a domain with a shared configuration rate limit rule. If a domain is associated with multiple shared rate limit rules, all associations take effect at the same time.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "ID of the association, in the format `<share_id>:<domain>`.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"share_id": schema.StringAttribute{
				Description: "ID of the shared rate limit rule.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "Domain name to be associated with the shared rate limit rule.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"service_type": schema.StringAttribute{
				Description: "Security service type, needed when multiple different security services are in use.",
				Optional:    true,
			},
		},
	}
}

func (r *sharedConfigRatelimitAssociationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*cdnetworksapi.Client)
}

func (r *sharedConfigRatelimitAssociationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model *sharedConfigRatelimitAssociationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	associateResponse, err := r.client.AssociateSharedRateLimitRule(model.ServiceType.ValueString(), &cdnetworksapi.AssociateSharedRateLimitRuleRequest{
		ShareID:    model.ShareId.ValueString(),
		DomainList: []string{model.Domain.ValueString()},
	})
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Create SharedConfigRateLimitAssociation", err.Error())
		return
	}
	if associateResponse.Code != 200 {
		resp.Diagnostics.AddError("[API ERROR] Fail to Create SharedConfigRateLimitAssociation", fmt.Sprintf("code: %s, msg: %s", associateResponse.Code, associateResponse.Msg))
		return
	}

	model.Id = types.StringValue(buildSharedConfigRatelimitAssociationId(model.ShareId.ValueString(), model.Domain.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *sharedConfigRatelimitAssociationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model *sharedConfigRatelimitAssociationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, err := findSharedRateLimitRule(r.client, model.ShareId.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Query SharedConfigRateLimitAssociation", err.Error())
		return
	}
	if rule == nil {
		// The shared rate limit rule no longer exists, so does the association.
		resp.State.RemoveResource(ctx)
		return
	}

	for _, domain := range rule.ShareRateLimitRelDomains {
		if domain == model.Domain.ValueString() {
			// The association still exists.
			resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
			return
		}
	}

	// The domain is no longer associated with the rule.
	resp.State.RemoveResource(ctx)
}

func (r *sharedConfigRatelimitAssociationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan *sharedConfigRatelimitAssociationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// `share_id` and `domain` force replacement, only `service_type` can be
	// updated in place and it only affects the serviceType header of the API
	// calls, so no API call is needed here.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sharedConfigRatelimitAssociationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var model *sharedConfigRatelimitAssociationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip the API call if the rule or the association no longer exists.
	rule, err := findSharedRateLimitRule(r.client, model.ShareId.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("[API ERROR] Fail to Query SharedConfigRateLimitAssociation", err.Error())
		return
	}
	if rule == nil {
		return
	}
	for _, domain := range rule.ShareRateLimitRelDomains {
		if domain == model.Domain.ValueString() {
			disassociateResponse, err := r.client.DisassociateSharedRateLimitRule(model.ServiceType.ValueString(), &cdnetworksapi.DisassociateSharedRateLimitRuleRequest{
				ShareID:    model.ShareId.ValueString(),
				DomainList: []string{model.Domain.ValueString()},
			})
			if err != nil {
				resp.Diagnostics.AddError("[API ERROR] Fail to Delete SharedConfigRateLimitAssociation", err.Error())
				return
			}
			if disassociateResponse.Code != 200 {
				resp.Diagnostics.AddError("[API ERROR] Fail to Delete SharedConfigRateLimitAssociation", fmt.Sprintf("code: %s, msg: %s", disassociateResponse.Code, disassociateResponse.Msg))
				return
			}
			return
		}
	}
}

func (r *sharedConfigRatelimitAssociationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, sharedConfigRatelimitAssociationIdSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("expected identifier in the format '<share_id>%s<domain>', got: %s", sharedConfigRatelimitAssociationIdSeparator, req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("share_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("domain"), parts[1])...)
}

// buildSharedConfigRatelimitAssociationId builds the composite id of the
// association from the share id and the domain.
func buildSharedConfigRatelimitAssociationId(shareId, domain string) string {
	return shareId + sharedConfigRatelimitAssociationIdSeparator + domain
}
