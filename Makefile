# [© EmberLabs® (BY-SA) (Attribution, Share-alike)](https://emberlabs.tech/copyright/)
# 
# - Similar to CC BY-SA
# - This license enables reusers to distribute, remix, adapt, and build upon the material in any medium or format, so long as attribution is given to the creator.
# - The license allows for commercial use.
# - If you remix, adapt, or build upon the material, you must license the modified material under identical terms.
# - A copy of the copyright license/terms must be retained as is in code or documents.
# - EmberLabs (BY-SA) includes the following elements:
#   - BY: Credit must be given to the creator.
#   - SA: Adaptations must be shared under the same terms.
# 
VERSION ?= 1.6.1

all: clean 
	# Set up and build. 
	go get -u "github.com/tidwall/gjson" 
	go get -u "github.com/1password/onepassword-sdk-go"
	go get -u all
	go build -ldflags="-X 'main.version=$(VERSION)'" -o 1PassMapper
	chmod 755 1PassMapper

deploy: all
	strip 1PassMapper
	mv 1PassMapper /bin/

test: all
	@rm -f dev.json stage.json prod.json
	./1PassMapper -injson sampleJsonCreds.json -in sample-template.json -prefix dev -out dev.json 
	./1PassMapper -injson sampleJsonCreds.json -in sample-template.json -prefix stage -out stage.json 
	./1PassMapper -injson sampleJsonCreds.json -in sample-template.json -prefix prod -out prod.json 
	@echo "-------------------------------------------------------------------------------------"
	@echo "Single source of truth file: sampleJsonCreds.json"
	@echo "--- Dev output ----------------------------------------------"
	@cat dev.json
	@echo "--- Stage output --------------------------------------------"
	@cat stage.json
	@echo "--- Prod output ---------------------------------------------"
	@cat prod.json
	@echo "-------------------------------------------------------------------------------------"
	
clean:
	# Clean up if we have remains. 
	rm -f dev.json stage.json prod.json 1PassMapper

