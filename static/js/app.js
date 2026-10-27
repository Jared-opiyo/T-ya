document.addEventListener("DOMContentLoaded", () => {
    const menuButton = document.querySelector(".menu-toggle");
    const navigation = document.querySelector("#main-navigation");

    if (menuButton && navigation) {
        menuButton.addEventListener("click", () => {
            const isOpen = navigation.classList.toggle("is-open");
            menuButton.setAttribute("aria-expanded", String(isOpen));
        });

        navigation.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => {
                navigation.classList.remove("is-open");
                menuButton.setAttribute("aria-expanded", "false");
            });
        });
    }

    const yearElement = document.querySelector("#current-year");
    if (yearElement) {
        yearElement.textContent = String(new Date().getFullYear());
    }
});
