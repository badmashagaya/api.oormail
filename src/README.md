For Prime Test

curl -X GET "https://oormail-services.by-oor.workers.dev/otp?platform=primevideo&secret=PPYZDSDAI5QG6R6LH6WF2DZ3JRH55V3AD54MGZQSZ2WZ5AFE66LA" \
     -H "x-api-key: OTTONTENT"


For Netflix with queue (Sign-in)

curl -X GET "https://oormail-services.by-oor.workers.dev/otp?platform=netflix&mail=yourtest@sharklasers.com&queue=true" \
     -H "x-api-key: OTTONTENT"

For Netflix without queue 

curl -X GET "https://oormail-services.by-oor.workers.dev/otp?platform=netflix&mail=yourtest@sharklasers.com" \
     -H "x-api-key: OTTONTENT"


For Netflix Household

curl -X GET "https://oormail-services.by-oor.workers.dev/household?mail=netflixhouseholdtest@sharklasers.com" \
     -H "x-api-key: OTTONTENT"
