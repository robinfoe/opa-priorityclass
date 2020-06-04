package kubernetes.admission

import data.kubernetes.namespaces

operations = {"CREATE", "UPDATE",}
kinds = {"Pod","Deployment"}

deny[msg] {
    run_check(input.request) 
    not priorityclass_match_any(input.request.object , valid_priority_class )
    msg := sprintf("Priority class is not in allowed list , allowed : %v",[get_allowed_classes])
}

## HELPER FUNCTION
run_check(doc){ 
    kinds[doc.kind.kind] ## kind Pod or Deployment
    operations[doc.operation] ## Operations CREATE or UPDATE
}

valid_priority_class = {pclass |
    whitelist := get_allowed_classes
    pclasses := split(whitelist, ",")
    pclass := pclasses[_]
}

## for pod
priorityclass_match_any(docs,patterns){
    docs.spec.priorityClassName
    priorityclass_match(docs.spec.priorityClassName,patterns[_])
}

## for deployment
priorityclass_match_any(docs,patterns){
    docs.spec.template.spec.priorityClassName
    priorityclass_match(docs.spec.template.spec.priorityClassName,patterns[_])
}

priorityclass_match(str,pattern){
    str == pattern
}

get_allowed_classes() = x {
    # x := "cat-1,cat-2,cat-3" 
    x := namespaces[input.request.namespace].metadata.annotations["allow-priority-class"]
}
