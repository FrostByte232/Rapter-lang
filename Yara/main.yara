show("This is a calculator!");

show("please enter number 1");
set num1 = inputNum();
show("Number 1 is :num1:");
show("please enter number 2");
set num2 = inputNum();
show("Number 2 is :num2:");
show("Enter an operator...");
set operator = input();

if (operator == "+") {
    set result = num1 + num2;
    show(result);
} elif (operator == "-") {
    set result = num1 - num2;
    show(result);
} elif (operator == "*") {
    set result = num1 * num2;
    show(result);
} elif (operator == "/") {
    set result = num1 / num2;
    show(result);
}