<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#--
  Built on the keycloak.v2 login theme macros so it renders exactly like the
  stock pages and inherits the realm's branding. A custom login theme must
  extend keycloak.v2 (the only login theme shipped with Keycloak 26).
-->
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('number'); section>
    <#if section = "header">
        ${msg("numberVerificationTitle")}
    <#elseif section = "form">
        <form id="kc-number-verification-form" class="${properties.kcFormClass!}"
              action="${url.loginAction}" method="post">

            <@field.group name="number" label=msg("numberVerificationLabel") error=messagesPerField.get("number") required=true>
                <span class="${properties.kcInputClass!} <#if messagesPerField.existsError('number')>${properties.kcError!}</#if>">
                    <input id="number" name="number" type="text"
                           autocomplete="off" autofocus inputmode="numeric"
                           maxlength="${(maxLength!64)?c}"
                           aria-describedby="number-help"
                           aria-invalid="<#if messagesPerField.existsError('number')>true</#if>"/>
                    <@field.errorIcon error=messagesPerField.get("number")/>
                </span>
                <div id="number-help" class="${properties.kcFormHelperTextClass!}">
                    <div class="${properties.kcInputHelperTextClass!}">
                        <div class="${properties.kcInputHelperTextItemClass!}">
                            <span class="${properties.kcInputHelperTextItemTextClass!}">${msg("numberVerificationHelp")}</span>
                        </div>
                    </div>
                </div>
            </@field.group>

            <@buttons.actionGroup>
                <@buttons.button id="kc-submit" name="verify" label="doSubmit"/>
            </@buttons.actionGroup>
        </form>
    </#if>
</@layout.registrationLayout>
