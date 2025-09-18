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

all:
	go get -u "github.com/tidwall/gjson"  
	go build
	chmod 755 1PassMapper
	strip 1PassMapper
	mv 1PassMapper /bin/
	
