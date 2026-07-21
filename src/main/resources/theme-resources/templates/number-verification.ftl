<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("numberVerificationTitle")}
    <#elseif section = "form">
        <form id="kc-number-verification-form" class="${properties.kcFormClass!}"
              action="${url.loginAction}" method="post">

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="number" class="${properties.kcLabelClass!}">
                        ${msg("numberVerificationLabel")}
                    </label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="number" name="number"
                           class="${properties.kcInputClass!}"
                           autocomplete="off" autofocus
                           inputmode="numeric"
                           aria-describedby="number-help"/>
                    <div id="number-help" class="${properties.kcInputHelperTextClass!}">
                        ${msg("numberVerificationHelp")}
                    </div>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           type="submit" value="${msg("doSubmit")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
