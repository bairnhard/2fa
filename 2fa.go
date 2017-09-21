package main

// 2fa = two factor authentication service

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
)

type Result struct {
	Token  string    `json:"token"`
	expiry time.Time `json:"expiry"`
}

func main() {

	log.Println(time.Now(), "2fa started")

	router := gin.Default()

	router.GET("/token", maketoken) //token generator

	router.Run()
}

func maketoken(whatever *gin.Context) {
	fmt.Println(whatever)
	tokenlength := 5

	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	var ergebnis []Result
	ergebnis = make([]Result, 10)

	for loop := 0; loop < 10; loop++ {

		b := make([]byte, tokenlength)
		for i := range b {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]

		}
		str := fmt.Sprintf("%x", b)
		exp := time.Now().Add(time.Minute * 5)
		ergebnis[loop] = Result{str, exp}

	}
	whatever.IndentedJSON(200, ergebnis)
}
