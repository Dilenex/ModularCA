using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services;

namespace ModularCA.API.Controllers.v1;

/// <summary>
/// Turns a <see cref="HeldKeyDelivery"/> into the HTTP answer the admin and user request
/// controllers both give, so the two endpoints cannot drift: the PKCS#12 as a download, 404 for
/// an unknown or foreign request, 400 for a weak password, and 409 with the reason when the
/// certificate is not issued yet, the key was already delivered, or no key was ever held.
/// </summary>
public static class HeldKeyDeliveryResults
{
    /// <summary>Maps <paramref name="delivery"/> to an action result on <paramref name="controller"/>.</summary>
    public static IActionResult ToResult(ControllerBase controller, HeldKeyDelivery delivery) => delivery.Outcome switch
    {
        HeldKeyDeliveryOutcome.Delivered => controller.File(delivery.Pkcs12!, "application/x-pkcs12", delivery.FileName),
        HeldKeyDeliveryOutcome.NotFound => controller.NotFound(new { error = delivery.Detail }),
        HeldKeyDeliveryOutcome.InvalidPassword => controller.BadRequest(new { error = delivery.Detail }),
        _ => controller.Conflict(new { error = delivery.Detail, outcome = delivery.Outcome.ToString() }),
    };
}
