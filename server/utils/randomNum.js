// Random numer between min and max
function randomNumber(min, max) {
    return Math.floor(
        Math.random() * (max - min) + min
    )
}

module.exports = randomNumber;