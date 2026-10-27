package phantom_test

import (
	"context"
	"fmt"
	"time"

	phantom "github.com/bywayhq/phantom/bindings/go"
)

func ExampleClient_Do() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := phantom.New(phantom.Config{
		Profile: "chrome-154-windows", Protocol: "negotiated", Context: "navigation",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	response, err := client.Do(ctx, phantom.Request{Method: "GET", URL: "https://example.com/"})
	if err != nil {
		fmt.Println(err)
		return
	}
	// ReadAll closes the body on success or failure and bounds memory use.
	data, err := response.Body.ReadAll(1024 * 1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(response.Status, len(data))
}

func ExampleClient_Do_requestContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := phantom.New(phantom.Config{
		Profile: "chrome-154-windows", Protocol: "negotiated", Context: "navigation",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	// The fetch request shares the client's connections and cookies.
	for _, request := range []phantom.Request{
		{Method: "GET", URL: "https://example.com/"},
		{Method: "GET", URL: "https://example.com/api", Context: "fetch"},
	} {
		response, err := client.Do(ctx, request)
		if err != nil {
			fmt.Println(err)
			return
		}
		// Close each body before the next request, including on a limit error.
		data, err := response.Body.ReadAll(1024 * 1024)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(response.Status, len(data))
	}
}
