<#import "template.ftl" as layout>
<#--
  Theme-agnostic on purpose: no imports beyond template.ftl, and every theme
  property is read with a fallback, so the form renders under base, the legacy
  keycloak theme, keycloak.v2, and any custom theme extending one of them.
  keycloak.v2 (PatternFly 5) wraps inputs in a form-control span; it is detected
  by a property that only exists there.
-->
<#assign hasError = messagesPerField.existsError('number')>
<#assign v2 = properties.kcFormLabelTextClass??>
<@layout.registrationLayout displayMessage=!hasError; section>
    <#if section = "header">
        ${msg("numberVerificationTitle")}
    <#elseif section = "form">
        <form id="kc-number-verification-form" class="${properties.kcFormClass!}"
              action="${url.loginAction}" method="post">

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!} ${properties.kcFormGroupLabelClass!}">
                    <label for="number" class="${properties.kcLabelClass!} ${properties.kcFormLabelClass!}">
                        <span class="${properties.kcFormLabelTextClass!}">${msg("numberVerificationLabel")}</span>
                    </label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <#if v2><span class="${properties.kcInputClass!} <#if hasError>${properties.kcError!}</#if>"></#if>
                    <input id="number" name="number" type="text"
                           <#if !v2>class="${properties.kcInputClass!}"</#if>
                           autocomplete="off" autofocus inputmode="numeric" dir="ltr"
                           maxlength="${(maxLength!64)?c}"
                           aria-describedby="number-help"
                           aria-invalid="<#if hasError>true</#if>"/>
                    <#if v2></span></#if>
                    <#if hasError>
                        <span id="input-error-number" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('number'))?no_esc}
                        </span>
                    </#if>
                    <div id="number-help" class="${properties.kcFormHelperTextClass!}">
                        <span class="${properties.kcInputHelperTextItemTextClass!}">${msg("numberVerificationHelp")}</span>
                    </div>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!} ${properties.kcFormActionGroupClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="verify" id="kc-verify" type="submit" value="${msg("doSubmit")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
