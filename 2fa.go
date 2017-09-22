package main

// 2fa = two factor authentication service

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const capletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const smalletters = "abcdefghijklmnopqrstuvwxyz"
const nums = "0123456789"
const symbols = "!@#$%^&*()-_=+,.?/:;{}[]`~"

type Result struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

func main() {

	log.Println(time.Now(), "2fa started")

	router := gin.Default()

	router.GET("/token", maketoken) //token generator

	router.GET("/send", sendmessage) //send token via SMS4A

	router.Run()
}

func sendmessage(dest *gin.Context) {

	destnum, _ := dest.GetQuery("dest") //destination number
	//TODO mobile number validation

	status, err := http.Get("https://sms4a.retarus.com/rest/v1/version")
	if err != nil {
		log.Println(time.Now(), err)
	}
	fmt.Println(status)
	fmt.Println(destnum)
	dest.String(200, "%v", status)

}

func maketoken(q *gin.Context) {

	qlen, _ := q.GetQuery("length") //how long should it be
	qtype, _ := q.GetQuery("type")  //what kind of token do we want to have?

	var LetterBytes string

	switch qtype {
	case "string":
		LetterBytes = capletters + smalletters

	case "lstring":
		LetterBytes = smalletters

	case "ustring":
		LetterBytes = capletters
	case "numbers":
		LetterBytes = nums
	case "symbol":
		LetterBytes = symbols + smalletters + capletters
	}

	tokenlength, err := strconv.Atoi(qlen)
	if err != nil {
		log.Println(time.Now(), "Incorrect length query parameter: ", err)
	}

	//tests
	fmt.Println("len: ", tokenlength)
	fmt.Println("type: ", qtype)
	fmt.Println("LetterBytes", LetterBytes)
	// const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	var ergebnis []Result
	ergebnis = make([]Result, 10)

	for loop := 0; loop < 10; loop++ {

		b := make([]byte, tokenlength)
		for i := range b {
			b[i] = LetterBytes[rand.Intn(len(LetterBytes))]

		}
		str := string(b[:])
		exp := time.Now().Add(time.Minute * 5)
		ergebnis[loop] = Result{str, exp}

	}
	q.IndentedJSON(200, ergebnis)
}
