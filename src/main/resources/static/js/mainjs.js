$(document).ready(function () {
    const showFeedback = function (message, type) {
        $("#feedback")
            .removeClass("d-none alert-success alert-danger")
            .addClass("alert-" + type)
            .text(message);
    };

    if ($("#login-form").length && new URLSearchParams(window.location.search).get("registered") === "true") {
        showFeedback("Đăng ký thành công. Bạn có thể đăng nhập.", "success");
    }

    $("#login-form").on("submit", function (event) {
        event.preventDefault();

        const loginData = JSON.stringify({
            email: $("#email").val().trim(),
            password: $("#password").val()
        });

        $.ajax({
            type: "POST",
            url: "/auth/login",
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            data: loginData,
            success: function (data) {
                localStorage.token = data.token;
                window.location.href = "/user/profile";
            },
            error: function (xhr) {
                const message = xhr.responseJSON && xhr.responseJSON.detail
                    ? xhr.responseJSON.detail
                    : "Đăng nhập thất bại.";
                showFeedback(message, "danger");
            }
        });
    });

    $("#signup-form").on("submit", function (event) {
        event.preventDefault();

        if ($("#password").val() !== $("#confirmPassword").val()) {
            showFeedback("Mật khẩu xác nhận không khớp.", "danger");
            return;
        }

        const signupData = JSON.stringify({
            fullName: $("#fullName").val().trim(),
            email: $("#email").val().trim(),
            password: $("#password").val()
        });

        $.ajax({
            type: "POST",
            url: "/auth/signup",
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            data: signupData,
            success: function () {
                window.location.href = "/login?registered=true";
            },
            error: function (xhr) {
                const message = xhr.responseJSON && xhr.responseJSON.detail
                    ? xhr.responseJSON.detail
                    : "Đăng ký thất bại.";
                showFeedback(message, "danger");
            }
        });
    });

    if ($("#profile").length) {
        if (!localStorage.token) {
            window.location.href = "/login";
            return;
        }

        $.ajax({
            type: "GET",
            url: "/users/me",
            dataType: "json",
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Bearer " + localStorage.token);
            },
            success: function (data) {
                $("#profile-name").text(data.fullName);
                $("#profile-email").text(data.email);
                $("#images").attr("src", data.images || "/images/default-avatar.svg");
            },
            error: function (xhr) {
                localStorage.removeItem("token");
                const message = xhr.responseJSON && xhr.responseJSON.detail
                    ? xhr.responseJSON.detail
                    : "Token không hợp lệ hoặc đã hết hạn.";
                showFeedback(message, "danger");
                setTimeout(function () {
                    window.location.href = "/login";
                }, 1200);
            }
        });
    }

    $("#logout").on("click", function () {
        localStorage.clear();
        window.location.href = "/login";
    });
});
