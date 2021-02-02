import 'mocha'
import { expect } from "chai"
import { say } from "../src/hello-word"

describe("hello-word", () => {
    it("Should display Hello World!", () => {
        expect(say()).to.eq("Hello World!")

    })
})
