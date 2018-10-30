package ee.xvf.bootmodauthoidc.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class EchoController {

    @GetMapping("/")
    fun echo(x: Any): String {

        return "lul"

    }

}